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
}

void test_moqtrun_nsx(void) {
  moqtrun_test_vers(0, MOQVER_CAP_PREFIX_OVERLAP, mtall_nsx_overlap);
  moqtrun_test_vers(MOQVER_CAP_PREFIX_OVERLAP, 0, mtall_nsx_untagged);
  moqtrun_test_allver(test_moqtrun_nsx_ns_narrow_implied_done);
}
