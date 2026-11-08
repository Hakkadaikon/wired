/* draft-23 overlapping namespace subscriptions at the hub: SUBSCRIBE_TRACKS
 * and SUBSCRIBE_NAMESPACE requests whose prefixes overlap are both served
 * (3.6, 4.2), each PUBLISH a SUBSCRIBE_TRACKS causes names it by
 * SUBSCRIBE_TRACKS_ID (9.19.21). Namespaces a, a/b, c; track t1 is a/b
 * (published by SESS_A), t2 is a (SESS_C); SESS_B subscribes. Shares the
 * fixtures of moqtrun_sub_test.c, moqtrun_ns_test.c,
 * moqtrun_subtracks_test.c, moqtrun_upd_test.c and moqtrun_upsub_test.c
 * (same unity TU). */

static u64 mnsx_ca;
static u64 mnsx_cc;

static void mnsx_init(void) {
  mtst_init();
  mnsx_ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mnsx_cc = mtst_join(SESS_C);
}

static moqctl_ftn mnsx_ftn(const char* ns, const char* name) {
  moqctl_ftn f = {0};
  f.ns         = mtns_ns(ns);
  f.name       = mtst_z(name);
  return f;
}

/* SESS_A PUBLISHes t1 (a/b), SESS_C PUBLISHes t2 (a). */
static void mnsx_pub_t1(void) {
  moqctl_ftn f = mnsx_ftn("a/b", "t1");
  mtst_publish(SESS_A, mnsx_ca, &f, 1);
  wired_moqt_tick(&mtst_hub, 0);
}

static void mnsx_pub_t2(void) {
  moqctl_ftn f = mnsx_ftn("a", "t2");
  mtst_publish(SESS_C, mnsx_cc, &f, 2);
  wired_moqt_tick(&mtst_hub, 0);
}

/* SESS_B's SUBSCRIBE_TRACKS on sid for prefix z; its Request ID. */
static u64 mnsx_st(u64 sid, const char* z) {
  mtst_subtracks(SESS_B, sid, z);
  return mtst_rid;
}

/* SUBSCRIBE_TRACKS_ID of a PUBLISH, ~0 when it carries none. */
static u64 mnsx_tag(const moqctl_publish* m) {
  const moqctl_param* p =
      moqctl_params_find(&m->params, MOQCTL_PARAM_SUBSCRIBE_TRACKS_ID);
  return p ? p->vi : ~(u64)0;
}

/* PUBLISHes the hub opened to SESS_B for track name tagged rid. */
static usz mnsx_pubs(u64 rid, const char* name) {
  moqctl_publish got[16];
  usz            n = mtst_pub_opens(SESS_B, got, 16), k = 0;
  wired_span     z = mtst_z(name);
  for (usz i = 0; i < n; i++) {
    k += mnsx_tag(&got[i]) == rid && got[i].name.name.n == z.n &&
         moqtrun_bytes_eq(got[i].name.name.p, z.p, z.n);
  }
  return k;
}

/* Every PUBLISH the hub opened to SESS_B. */
static usz mnsx_pubs_all(void) {
  moqctl_publish got[16];
  return mtst_pub_opens(SESS_B, got, 16);
}

/* The one PUBLISH s1 caused is answered, so SESS_B holds a subscription
 * to t1 when s2 arrives: s2 still gets its own PUBLISH (3.6 "If a Track
 * matches more than one SUBSCRIBE_TRACKS, the publisher sends a PUBLISH
 * for each"). */
static void test_moqtrun_nsx_overlap_tracks_each_publish(void) {
  mnsx_init();
  mnsx_pub_t1();
  u64 s1 = mnsx_st(MTRQ_S1, "a");
  CHECK(mnsx_pubs(s1, "t1") == 1);
  mtst_pub_ok(SESS_B, (u64)mtst_pub_stream_id(0));
  u64 s2 = mnsx_st(MTRQ_S2, "a");
  CHECK(mtst_stlog_is(SESS_B, MTRQ_S2, "OK|"));
  CHECK(mnsx_pubs(s2, "t1") == 1);
  CHECK(mnsx_pubs(s1, "t1") == 1);
  CHECK(mnsx_pubs_all() == 2);
}

/* 3.6: a track arriving after two overlapping requests reaches both. */
static void test_moqtrun_nsx_track_after_two_requests(void) {
  mnsx_init();
  u64 s1 = mnsx_st(MTRQ_S1, "a");
  u64 s2 = mnsx_st(MTRQ_S2, "a/b");
  CHECK(mtst_stlog_is(SESS_B, MTRQ_S2, "OK|"));
  mnsx_pub_t1();
  CHECK(mnsx_pubs(s1, "t1") == 1);
  CHECK(mnsx_pubs(s2, "t1") == 1);
  CHECK(mnsx_pubs_all() == 2);
}

/* 2.4.2: prefix a/b does not match namespace a. */
static void test_moqtrun_nsx_track_outside_prefix(void) {
  mnsx_init();
  mnsx_st(MTRQ_S1, "a/b");
  mnsx_pub_t2();
  CHECK(mnsx_pubs_all() == 0);
}

/* 3.6: a cancelled SUBSCRIBE_TRACKS causes no further PUBLISH. */
static void test_moqtrun_nsx_tracks_cancel_stops(void) {
  mnsx_init();
  mnsx_st(MTRQ_S1, "a");
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S1, 0, 0);
  mnsx_pub_t1();
  CHECK(mnsx_pubs_all() == 0);
}

/* 4.2: two overlapping SUBSCRIBE_NAMESPACE are both accepted and each is
 * told of a/b, with the suffix relative to its own prefix. */
static void test_moqtrun_nsx_overlap_ns_both(void) {
  mnsx_init();
  mtns_pub(SESS_A, MTRQ_S1, "a/b");
  mtns_sub(SESS_B, MTRQ_S1, "a");
  mtns_sub(SESS_B, MTRQ_S2, "a/b");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:b|"));
  CHECK(mtns_is(SESS_B, MTRQ_S2, "OK|NS:|"));
}

/* 4.2: c matches no prefix: neither NAMESPACE nor NAMESPACE_DONE. */
static void test_moqtrun_nsx_unmatched_ns_silent(void) {
  mnsx_init();
  mtns_sub(SESS_B, MTRQ_S1, "a");
  mtns_pub(SESS_A, MTRQ_S1, "c");
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S1, 0, 0);
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|"));
}

/* 4.2: a cancelled SUBSCRIBE_NAMESPACE is told nothing more. */
static void test_moqtrun_nsx_ns_cancel_stops(void) {
  mnsx_init();
  mtns_sub(SESS_B, MTRQ_S1, "a");
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S1, 0, 0);
  mtns_pub(SESS_A, MTRQ_S1, "a");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|"));
}

/* 9.19.21: SUBSCRIBE_TRACKS_ID appears only in a PUBLISH sent as a result
 * of a SUBSCRIBE_TRACKS, and the hub sends none: a client's PUBLISH
 * carrying it closes the session INVALID_PARAMETER. */
static void test_moqtrun_nsx_client_publish_tagged(void) {
  moqctl_params p = {0};
  moqctl_ftn    f = mnsx_ftn("a/b", "t1");
  mnsx_init();
  p.items[0].type = MOQCTL_PARAM_SUBSCRIBE_TRACKS_ID;
  p.items[0].enc  = MOQCTL_PENC_VARINT;
  p.items[0].vi   = 4;
  p.n             = 1;
  mtst_publish_p(SESS_A, mnsx_ca, &f, 1, &p);
  CHECK(mtrq_closes_cc(WIRED_MOQTRUN_CLOSE_INVALID_PARAMETER) == 1);
}

/* SESS_B's REQUEST_UPDATE of the request on sid to prefix z. */
static void mnsx_update(u64 sid, const char* z) {
  moqctl_params p = mtup_ns_param(z);
  mtup_update(SESS_B, sid, &p);
  wired_moqt_tick(&mtst_hub, 0);
}

/* 9.5.2: narrowing a SUBSCRIBE_TRACKS prefix to one t1 still matches
 * sends no second PUBLISH for t1 on that request. */
static void test_moqtrun_nsx_tracks_update_no_republish(void) {
  mnsx_init();
  mnsx_pub_t1();
  u64 s1 = mnsx_st(MTRQ_S1, "a");
  mnsx_update(MTRQ_S1, "a/b");
  CHECK(mtst_stlog_is(SESS_B, MTRQ_S1, "OK|OK|"));
  CHECK(mnsx_pubs(s1, "t1") == 1);
  CHECK(mnsx_pubs_all() == 1);
}

/* Widening a SUBSCRIBE_TRACKS prefix PUBLISHes the live tracks that newly
 * match, as for a track starting after the request, and never one already
 * published for it (9.5.2). */
static void test_moqtrun_nsx_tracks_widen_publishes_new(void) {
  mnsx_init();
  mnsx_pub_t1();
  mnsx_pub_t2();
  u64 s1 = mnsx_st(MTRQ_S1, "a/b");
  CHECK(mnsx_pubs(s1, "t1") == 1);
  mnsx_update(MTRQ_S1, "a");
  CHECK(mnsx_pubs(s1, "t2") == 1);
  CHECK(mnsx_pubs(s1, "t1") == 1);
  CHECK(mnsx_pubs_all() == 2);
}

/* 9.5.2: narrowed and widened back, the request is PUBLISHed nothing
 * twice. */
static void test_moqtrun_nsx_tracks_narrow_rewiden(void) {
  mnsx_init();
  mnsx_pub_t1();
  mnsx_pub_t2();
  u64 s1 = mnsx_st(MTRQ_S1, "a");
  CHECK(mnsx_pubs_all() == 2);
  mnsx_update(MTRQ_S1, "a/b");
  mnsx_update(MTRQ_S1, "a");
  CHECK(mnsx_pubs(s1, "t1") == 1);
  CHECK(mnsx_pubs(s1, "t2") == 1);
  CHECK(mnsx_pubs_all() == 2);
}

/* 9.5.2: the REQUEST_OK of a narrowing update implies NAMESPACE_DONE for
 * a, so none is sent then -- nor later, when a is withdrawn (a has no
 * suffix past a/b; every draft). */
static void test_moqtrun_nsx_ns_narrow_implied_done(void) {
  mnsx_init();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mtns_sub(SESS_B, MTRQ_S1, "a");
  mnsx_update(MTRQ_S1, "a/b");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:|OK|"));
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S1, 0, 0);
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:|OK|"));
}

/* 9.5.2: widening a/b to a advertises a, not a/b again (its suffix is now
 * "b"). */
static void test_moqtrun_nsx_ns_widen_new_only(void) {
  mnsx_init();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mtns_pub(SESS_A, MTRQ_S2, "a/b");
  mtns_sub(SESS_B, MTRQ_S1, "a/b");
  mnsx_update(MTRQ_S1, "a");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:|OK|NS:|"));
}

/* 9.5.2: a dropped by a narrowing update is advertised again once the
 * prefix covers it again. */
static void test_moqtrun_nsx_ns_narrow_rewiden(void) {
  mnsx_init();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mtns_sub(SESS_B, MTRQ_S1, "a");
  mnsx_update(MTRQ_S1, "a/b");
  mnsx_update(MTRQ_S1, "a");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:|OK|OK|NS:|"));
}

/* 2.4.2: prefix matching is field by field: prefix a covers a/b, not ab. */
static void test_moqtrun_nsx_prefix_fieldwise(void) {
  moqctl_ftn f = mnsx_ftn("ab", "t3");
  mnsx_init();
  mtns_pub(SESS_A, MTRQ_S1, "ab");
  mtns_pub(SESS_A, MTRQ_S2, "a/b");
  mtns_sub(SESS_B, MTRQ_S1, "a");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:b|"));
  mtst_publish(SESS_C, mnsx_cc, &f, 3);
  mnsx_pub_t1();
  u64 s1 = mnsx_st(MTRQ_S2, "a");
  CHECK(mnsx_pubs(s1, "t1") == 1);
  CHECK(mnsx_pubs_all() == 1);
}

/* 4.1: the same prefix announced twice in one session stays published
 * until both are withdrawn; each gets its own REQUEST_OK. */
static void test_moqtrun_nsx_refcount_one_withdraw_still_known(void) {
  mnsx_init();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mtns_pub(SESS_A, MTRQ_S2, "a");
  CHECK(mtns_is(SESS_A, MTRQ_S2, "OK|"));
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S1, 0, 0);
  mtns_sub(SESS_B, MTRQ_S1, "a");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:|"));
}

/* 4.1 / 4.2: NAMESPACE_DONE only once the last duplicate is withdrawn. */
static void test_moqtrun_nsx_refcount_done_on_last(void) {
  mnsx_init();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mtns_pub(SESS_A, MTRQ_S2, "a");
  mtns_sub(SESS_B, MTRQ_S1, "a");
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S1, 0, 0);
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:|"));
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S2, 0, 0);
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:|DONE:|"));
}

/* 4.2: a announced by two sessions is advertised once and stays so while
 * either still publishes it. */
static void test_moqtrun_nsx_two_publishers_same_ns(void) {
  mnsx_init();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mtns_pub(SESS_C, MTRQ_S1, "a");
  mtns_sub(SESS_B, MTRQ_S1, "a");
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S1, 0, 0);
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:|"));
}

/* Upstream SUBSCRIBE (7.7) in relay mode (hub->multi_publisher). */
static void mnsx_relay(void) {
  mnsx_init();
  mtst_hub.multi_publisher = 1;
  g_next_stream_id         = 201; /* server-initiated bidi ids */
}

/* SESS_B SUBSCRIBEs t1 on sid. */
static void mnsx_dsub(u64 sid) {
  moqctl_ftn f = mnsx_ftn("a/b", "t1");
  mtst_subscribe_p(SESS_B, sid, &f, mtst_rid += 4, 0);
}

/* 7.7: a second PUBLISH_NAMESPACE of a by SESS_A, which the hub already
 * subscribed t1 at, sends no second SUBSCRIBE ("unless it already has a
 * subscription to that Track from that publisher"). */
static void test_moqtrun_nsx_dup_pubns_no_resubscribe(void) {
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mnsx_dsub(MTRQ_S1);
  CHECK(mups_n_up(SESS_A) == 1);
  mtns_pub(SESS_A, MTRQ_S2, "a");
  CHECK(mups_n_up(SESS_A) == 1);
}

/* 7.7: two announcements of SESS_A covering t1 (a, a/b): one SUBSCRIBE. */
static void test_moqtrun_nsx_overlap_pubns_one_subscribe(void) {
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mtns_pub(SESS_A, MTRQ_S2, "a/b");
  mnsx_dsub(MTRQ_S1);
  CHECK(mups_n_up(SESS_A) == 1);
}

/* 7.7: every session announcing a prefix of t1's namespace is asked, not
 * only the exact match (4.1's SHOULD gives way to 7.7's MUST). */
static void test_moqtrun_nsx_subscribe_every_announcer(void) {
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a/b");
  mtns_pub(SESS_C, MTRQ_S1, "a");
  mnsx_dsub(MTRQ_S1);
  CHECK(mups_n_up(SESS_A) == 1);
  CHECK(mups_n_up(SESS_C) == 1);
}

/* 7.7: SESS_A already PUBLISHed t1, so its later announcement of a/b is
 * not answered with a SUBSCRIBE for t1. */
static void test_moqtrun_nsx_no_subscribe_after_publish(void) {
  mnsx_relay();
  mnsx_pub_t1();
  mnsx_dsub(MTRQ_S1);
  mtns_pub(SESS_A, MTRQ_S1, "a/b");
  CHECK(mups_n_up(SESS_A) == 0);
}

/* 7.7: a withdrawn and re-sent announcement keeps the existing upstream
 * subscription: no second SUBSCRIBE. */
static void test_moqtrun_nsx_reannounce_no_resubscribe(void) {
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mnsx_dsub(MTRQ_S1);
  mups_ok((u64)mups_up_sid());
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S1, 0, 0);
  mtns_pub(SESS_A, MTRQ_S2, "a");
  CHECK(mups_n_up(SESS_A) == 1);
}

/* 7.7: an announcement of c does not cover t1 (a/b). */
static void test_moqtrun_nsx_no_subscribe_uncovered(void) {
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "c");
  mnsx_dsub(MTRQ_S1);
  CHECK(mups_n_up(SESS_A) == 0);
}

/* 7.7: an announcement alone, with nobody subscribed downstream, sends no
 * SUBSCRIBE. */
static void test_moqtrun_nsx_no_subscribe_without_downstream(void) {
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  CHECK(mups_n_up(SESS_A) == 0);
}

/* 7.7: a second downstream SUBSCRIBE to t1 rides the pending upstream
 * one. */
static void test_moqtrun_nsx_second_dsub_no_resubscribe(void) {
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mnsx_dsub(MTRQ_S1);
  mnsx_dsub(MTRQ_S2);
  CHECK(mups_n_up(SESS_A) == 1);
}

/* SUBSCRIBE_OK from s on the hub's upstream stream sid. */
static void mnsx_up_ok(wired_wt_session* s, u64 sid) {
  static moqctl_subscribe_ok ok;
  ok.track_alias = MUPS_ALIAS;
  mtst_send(s, sid, MOQCTL_T_SUBSCRIBE_OK, mups_enc_ok, &ok);
}

/* t1 fanned out to SESS_A (a/b) and SESS_C (a); their stream ids. */
static void mnsx_fan(i64* sa, i64* sc) {
  moqctl_subscribe m;
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a/b");
  mtns_pub(SESS_C, MTRQ_S1, "a");
  mnsx_dsub(MTRQ_S1);
  *sa = mups_up(SESS_A, 0, &m);
  *sc = mups_up(SESS_C, 0, &m);
}

/* A few hub steps with no new request or announcement. */
static void mnsx_syncs(void) {
  for (u64 t = 1; t <= 3; t++) {
    wired_moqt_tick(&mtst_hub, t);
  }
}

/* 7.7: one announcer refusing while another answers OK: SUBSCRIBE_OK.
 * Without a new downstream SUBSCRIBE or PUBLISH_NAMESPACE the refusing
 * announcer is not asked again, before or after the other one's OK. */
static void test_moqtrun_nsx_fan_one_fails(void) {
  i64 sa, sc;
  mnsx_fan(&sa, &sc);
  mtst_pub_err(SESS_C, (u64)sc, MOQCTL_ERR_DOES_NOT_EXIST);
  CHECK(mrdv_is(SESS_B, MTRQ_S1, ""));
  mnsx_syncs();
  CHECK(mups_n_up(SESS_C) == 1);
  mnsx_up_ok(SESS_A, (u64)sa);
  CHECK(mrdv_is(SESS_B, MTRQ_S1, "SOK|"));
  mnsx_syncs();
  CHECK(mups_n_up(SESS_C) == 1);
}

/* 7.7: every announcer refusing: REQUEST_ERROR with the last code. */
static void test_moqtrun_nsx_fan_all_fail(void) {
  i64 sa, sc;
  mnsx_fan(&sa, &sc);
  mtst_pub_err(SESS_A, (u64)sa, MOQCTL_ERR_UNAUTHORIZED);
  mtst_pub_err(SESS_C, (u64)sc, MOQCTL_ERR_DOES_NOT_EXIST);
  CHECK(mrdv_is(SESS_B, MTRQ_S1, "E10|FIN|"));
}

/* A refused upstream SUBSCRIBE is forgotten: the next downstream
 * SUBSCRIBE asks the publisher again. */
static void test_moqtrun_nsx_refused_then_resent(void) {
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mnsx_dsub(MTRQ_S1);
  mtst_pub_err(SESS_A, (u64)mups_up_sid(), MOQCTL_ERR_UNAUTHORIZED);
  CHECK(mrdv_is(SESS_B, MTRQ_S1, "E1|FIN|"));
  mnsx_dsub(MTRQ_S2);
  CHECK(mups_n_up(SESS_A) == 2);
}

/* 7.7 fan-out: the downstream SUBSCRIBE_OK given on A's OK stands when C
 * refuses afterwards -- no REQUEST_ERROR follows it. */
static void test_moqtrun_nsx_fanout_fail_after_ok(void) {
  i64 sa, sc;
  mnsx_fan(&sa, &sc);
  mnsx_up_ok(SESS_A, (u64)sa);
  CHECK(mrdv_is(SESS_B, MTRQ_S1, "SOK|"));
  mtst_pub_err(SESS_C, (u64)sc, MOQCTL_ERR_DOES_NOT_EXIST);
  CHECK(mrdv_is(SESS_B, MTRQ_S1, "SOK|"));
}

/* 7.7: while both upstream SUBSCRIBEs are pending, the owner A PUBLISHes
 * t1: the waiting downstream SUBSCRIBE is answered SUBSCRIBE_OK, and C's
 * later refusal sends no REQUEST_ERROR. */
static void test_moqtrun_nsx_fanout_owner_publish_ok(void) {
  i64 sa, sc;
  mnsx_fan(&sa, &sc);
  mnsx_pub_t1();
  CHECK(mrdv_is(SESS_B, MTRQ_S1, "SOK|"));
  mtst_pub_err(SESS_C, (u64)sc, MOQCTL_ERR_DOES_NOT_EXIST);
  CHECK(mrdv_is(SESS_B, MTRQ_S1, "SOK|"));
}

/* 7.7: once the owner A has PUBLISHed t1 and its upstream SUBSCRIBE
 * fails, a new downstream SUBSCRIBE rides A's published track: no new
 * SUBSCRIBE goes to A. */
static void test_moqtrun_nsx_resend_skips_publisher(void) {
  i64 sa, sc;
  mnsx_fan(&sa, &sc);
  mnsx_pub_t1();
  mtst_pub_err(SESS_A, (u64)sa, MOQCTL_ERR_UNAUTHORIZED);
  mnsx_dsub(MTRQ_S2);
  mnsx_syncs();
  CHECK(mups_n_up(SESS_A) == 1);
}

/* 7.7: the only announcer refuses, is asked again on the next downstream
 * SUBSCRIBE, and refuses again: that SUBSCRIBE fails too. */
static void test_moqtrun_nsx_second_fail_error(void) {
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mnsx_dsub(MTRQ_S1);
  mtst_pub_err(SESS_A, (u64)mups_up_sid(), MOQCTL_ERR_UNAUTHORIZED);
  mnsx_dsub(MTRQ_S2);
  CHECK(mups_n_up(SESS_A) == 2);
  moqctl_subscribe m;
  mtst_pub_err(SESS_A, (u64)mups_up(SESS_A, 1, &m), MOQCTL_ERR_UNAUTHORIZED);
  CHECK(mrdv_is(SESS_B, MTRQ_S2, "E1|FIN|"));
}

/* The only announcer's session lost while the upstream SUBSCRIBE is
 * pending: REQUEST_ERROR INTERNAL_ERROR on draft-23, DOES_NOT_EXIST on
 * earlier drafts (no publisher left, 10.2.6). */
static void mnsx_lost_publisher(void) {
  int d23 = (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_UP_LOSS) != 0;
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mnsx_dsub(MTRQ_S1);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mrdv_is(SESS_B, MTRQ_S1, d23 ? "E0|FIN|" : "E10|FIN|"));
}

/* SESS_B's SUBSCRIBE_TRACKS for chat carrying FILL_PARAMETERS (an
 * open-ended fill), paused when paused; mf_init's alice matches. */
static void mnsx_st_fill(int paused) {
  static moqns_req m;
  moqfetch_fill    fill              = {0};
  m.request_id                       = mtst_rid += 4;
  m.ns                               = mtns_ns("chat");
  m.params                           = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  m.params.n                         = paused != 0;
  m.params                           = mfill_params(&fill, &m.params);
  m.params.items[m.params.n - 1].enc = MOQCTL_PENC_FILL23;
  mtst_send(SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE_TRACKS, mtst_enc_subtracks, &m);
}

/* 3.4.1 / 9.19.15: each PUBLISH the hub sends for a SUBSCRIBE_TRACKS
 * carrying FILL_PARAMETERS carries them too, and the fill fetch stream
 * opens as the PUBLISH goes out (no PUBLISH_OK awaited), its FETCH_HEADER
 * naming the PUBLISH's Request ID. */
static void test_moqtrun_nsx_tracks_fill_opens(void) {
  moqctl_publish got[2];
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  mnsx_st_fill(0);
  CHECK(mtst_pub_opens(SESS_B, got, 2) == 1);
  CHECK(moqctl_params_find(&got[0].params, MOQCTL_PARAM_FILL_PARAMETERS));
  moqfetch_seq seq  = {0};
  seq.eor_timed_out = 1;
  CHECK(mf_read_seq(seq) && mf_hdr_rid == got[0].request_id && mf_fin);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(mf_n - 1, 1, 0, 1));
}

/* 3.4.1: a paused PUBLISH opens no fill stream. */
static void test_moqtrun_nsx_tracks_fill_paused(void) {
  moqctl_publish got[2];
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mnsx_st_fill(1);
  CHECK(mtst_pub_opens(SESS_B, got, 2) == 1);
  CHECK(mfill_opens() == 0);
}

/* A FILL_PARAMETERS value longer than the hub keeps (one 70-byte
 * AUTHORIZATION_TOKEN: count 1, Type 0x03, Length 70, USE_VALUE, Token
 * Type 0, 68 bytes) refuses the SUBSCRIBE_TRACKS INTERNAL_ERROR. */
static void test_moqtrun_nsx_tracks_fill_too_long(void) {
  static u8        v[73];
  static moqns_req m;
  mnsx_init();
  bytes_memset(v, 'x', sizeof v);
  v[0]                    = 1;
  v[1]                    = 0x03;
  v[2]                    = 70;
  v[3]                    = MOQCTL_TOKEN_USE_VALUE;
  v[4]                    = 0;
  m.request_id            = mtst_rid += 4;
  m.ns                    = mtns_ns("a");
  m.params.n              = 1;
  m.params.items[0].type  = MOQCTL_PARAM_FILL_PARAMETERS;
  m.params.items[0].enc   = MOQCTL_PENC_FILL23;
  m.params.items[0].bytes = wired_span_of(v, sizeof v);
  mtst_send(SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE_TRACKS, mtst_enc_subtracks, &m);
  CHECK(mtst_stlog_is(SESS_B, MTRQ_S1, "ERR:00|"));
}

/* A PUBLISH carrying FILL_PARAMETERS whose fill parks mid-range, open;
 * the PUBLISH's stream id. */
static u64 mnsx_fill_parked(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  g_stream_send_ok_n = 0;
  mnsx_st_fill(0);
  g_stream_send_ok_n = -1;
  CHECK(mfill_opens() == 1 && !mf_no_fetch());
  return (u64)mtst_pub_stream_id(0);
}

/* 3.4.1 "When the subscription is cancelled, the publisher MUST reset any
 * open fill fetch streams": a PUBLISH rejected with REQUEST_ERROR never
 * became a subscription, so its fill is reset CANCELLED (12.5). */
static void test_moqtrun_nsx_tracks_fill_rejected_resets(void) {
  mtst_pub_err(SESS_B, mnsx_fill_parked(), MOQCTL_ERR_UNINTERESTED);
  CHECK(mfill_reset_code(mfill_sid(0)) == MOQTRUN_RESET_CANCELLED);
  CHECK(mf_no_fetch());
}

/* 3.4.1 / 6.4.2.3: the subscriber cancelling the PUBLISH (its stream
 * reset) resets the fill CANCELLED (12.5). */
static void test_moqtrun_nsx_tracks_fill_cancel_resets(void) {
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, mnsx_fill_parked(), 0, 0);
  CHECK(mfill_reset_code(mfill_sid(0)) == MOQTRUN_RESET_CANCELLED);
  CHECK(mf_no_fetch());
}

/* 3.4.1: a PUBLISH_OK the hub cannot attach (the track's subs[] full)
 * leaves no subscription, so the fill is reset too. */
static void test_moqtrun_nsx_tracks_fill_unattached_resets(void) {
  u64                  sid = mnsx_fill_parked();
  wired_moqtrun_track* t =
      moqtrun_pubst_track(&mtst_hub, mtst_hub.cache_tag_next);
  CHECK(t != 0);
  for (usz i = 0; t && i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    t->subs[i].active = 1;
  }
  mtst_pub_ok(SESS_B, sid);
  CHECK(mfill_reset_code(mfill_sid(0)) == MOQTRUN_RESET_CANCELLED);
  CHECK(mf_no_fetch());
}

/* FILL_PARAMETERS on SUBSCRIBE_TRACKS: draft-23 only (9.19.15). */
static void mtall_nsx_fill(void) {
  test_moqtrun_nsx_tracks_fill_opens();
  test_moqtrun_nsx_tracks_fill_paused();
  test_moqtrun_nsx_tracks_fill_too_long();
  test_moqtrun_nsx_tracks_fill_rejected_resets();
  test_moqtrun_nsx_tracks_fill_cancel_resets();
  test_moqtrun_nsx_tracks_fill_unattached_resets();
}

/* Drafts with PREFIX_OVERLAP: the hub's PUBLISH has no
 * SUBSCRIBE_TRACKS_ID (the parameter does not exist there). */
static void mtall_nsx_untagged(void) {
  moqctl_publish got[2];
  mnsx_init();
  mnsx_pub_t1();
  mnsx_st(MTRQ_S1, "a");
  CHECK(mtst_pub_opens(SESS_B, got, 2) == 1);
  CHECK(mnsx_tag(&got[0]) == ~(u64)0);
}

static void mtall_nsx_overlap(void) {
  test_moqtrun_nsx_overlap_tracks_each_publish();
  test_moqtrun_nsx_track_after_two_requests();
  test_moqtrun_nsx_track_outside_prefix();
  test_moqtrun_nsx_tracks_cancel_stops();
  test_moqtrun_nsx_overlap_ns_both();
  test_moqtrun_nsx_unmatched_ns_silent();
  test_moqtrun_nsx_ns_cancel_stops();
  test_moqtrun_nsx_client_publish_tagged();
  test_moqtrun_nsx_tracks_update_no_republish();
  test_moqtrun_nsx_tracks_widen_publishes_new();
  test_moqtrun_nsx_tracks_narrow_rewiden();
  test_moqtrun_nsx_ns_widen_new_only();
  test_moqtrun_nsx_ns_narrow_rewiden();
  test_moqtrun_nsx_prefix_fieldwise();
  test_moqtrun_nsx_refcount_one_withdraw_still_known();
  test_moqtrun_nsx_refcount_done_on_last();
  test_moqtrun_nsx_two_publishers_same_ns();
  test_moqtrun_nsx_dup_pubns_no_resubscribe();
  test_moqtrun_nsx_overlap_pubns_one_subscribe();
  test_moqtrun_nsx_subscribe_every_announcer();
  test_moqtrun_nsx_no_subscribe_after_publish();
  test_moqtrun_nsx_reannounce_no_resubscribe();
  test_moqtrun_nsx_no_subscribe_uncovered();
  test_moqtrun_nsx_no_subscribe_without_downstream();
  test_moqtrun_nsx_second_dsub_no_resubscribe();
  test_moqtrun_nsx_fan_one_fails();
  test_moqtrun_nsx_fan_all_fail();
  test_moqtrun_nsx_refused_then_resent();
  test_moqtrun_nsx_fanout_fail_after_ok();
  test_moqtrun_nsx_fanout_owner_publish_ok();
  test_moqtrun_nsx_resend_skips_publisher();
  test_moqtrun_nsx_second_fail_error();
}

void test_moqtrun_nsx(void) {
  moqtrun_test_vers(0, MOQVER_CAP_PREFIX_OVERLAP, mtall_nsx_overlap);
  moqtrun_test_vers(MOQVER_CAP_PREFIX_OVERLAP, 0, mtall_nsx_untagged);
  moqtrun_test_allver(test_moqtrun_nsx_ns_narrow_implied_done);
  moqtrun_test_allver(mnsx_lost_publisher);
  moqtrun_test_vers(MOQVER_CAP_FILL_COUNT, 0, mtall_nsx_fill);
}
