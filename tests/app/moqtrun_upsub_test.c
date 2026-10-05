/* Upstream SUBSCRIBE (ledger 12-3): a SUBSCRIBE missing every PUBLISHed
 * track whose namespace a session announced with PUBLISH_NAMESPACE is
 * sent upstream to that publisher, and answered SUBSCRIBE_OK only once
 * the upstream subscription is Established (draft-ietf-moq-transport-
 * 18/19 9.4-9.5, draft-22 7.4/7.6). One upstream subscription serves every
 * downstream subscriber of the Track. Scenarios map to UpstreamSub.tla's
 * invariants. Shares the recording io stubs (moqtrun_test.c) and the
 * fixtures of moqtrun_sub_test.c, moqtrun_ns_test.c,
 * moqtrun_subtracks_test.c and moqtrun_rdv_test.c (same unity TU). */

#define MUPS_ALIAS 7
#define MUPS_DATA_SID 1001

/* The hub's next opened stream gets a server-initiated bidi id (1 mod 4,
 * RFC 9000 2.1), as in production -- a stale reply on it is then never
 * mistaken for a client request stream (moqtrun_req_stream_ok). */
static void mups_sids(void) { g_next_stream_id = 201; }

/* A announces chat/room1 on its request stream MRDV_S1. */
static void mups_announce(void) { mtns_pub(SESS_A, MRDV_S1, "chat/room1"); }

/* A, B joined at clock 0 under the drafts pv / sv; A announced. */
static void mups_init_v(int pv, int sv) {
  mrdv_init();
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->ver = pv;
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = sv;
  mups_announce();
  mups_sids();
}

static void mups_init(void) {
  mups_init_v(g_moqtrun_test_ver, g_moqtrun_test_ver);
}

/* s SUBSCRIBEs the awaited track, no RENDEZVOUS_TIMEOUT. */
static void mups_sub(wired_wt_session* s, u64 sid) {
  moqctl_ftn f = mrdv_f();
  mtst_subscribe_p(s, sid, &f, mtst_rid += 2, 0);
}

/* The which-th SUBSCRIBE the hub opened toward s (decoded in s's draft
 * into *m, its stream id returned); -1 if there is none. */
static i64 mups_up(wired_wt_session* s, usz which, moqctl_subscribe* m) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0, boff = 0;
    u64                      type;
    wired_span               body;
    if (c->kind != 1 || c->s != s) continue;
    moqctl_peek_type(
        wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type != MOQCTL_T_SUBSCRIBE) continue;
    if (n++ != which) continue;
    CHECK(moqctl_subscribe_take(mtst_ver(s), body, &boff, m) == MOQCTL_OK);
    return (i64)c->stream_id;
  }
  return -1;
}

/* Upstream SUBSCRIBEs opened toward s. */
static usz mups_n_up(wired_wt_session* s) {
  moqctl_subscribe m;
  usz              n = 0;
  while (mups_up(s, n, &m) >= 0) n++;
  return n;
}

static i64 mups_up_sid(void) {
  moqctl_subscribe m;
  return mups_up(SESS_A, 0, &m);
}

static int mups_enc_ok(wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_ok_encode(buf, off, m);
}

static int mups_enc_done(wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_done_encode(buf, off, m);
}

/* A answers SUBSCRIBE_OK (Track Alias MUPS_ALIAS) on its stream sid. */
static void mups_ok(u64 sid) {
  static moqctl_subscribe_ok ok;
  ok.track_alias = MUPS_ALIAS;
  mtst_send(SESS_A, sid, MOQCTL_T_SUBSCRIBE_OK, mups_enc_ok, &ok);
}

static void mups_done(u64 sid, u64 status) {
  static moqctl_publish_done d;
  d.status_code  = status;
  d.stream_count = 0;
  mtst_send(SESS_A, sid, MOQCTL_T_PUBLISH_DONE, mups_enc_done, &d);
}

/* Upstream entries in use. */
static usz mups_used(void) {
  usz n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++)
    n += mtst_hub.ups[i].in_use != 0;
  return n;
}

/* Hub ops on A's upstream stream sid: "RST<code>|", "STOP<code>|",
 * "FIN|", in order. */
static const char* mups_up_log(u64 sid) {
  mrdv_at = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    if (c->s != SESS_A || c->stream_id != sid) continue;
    if (c->kind == 6) mrdv_put("FIN|");
    if (c->kind == 7) mrdv_put("RST");
    if (c->kind == 13) mrdv_put("STOP");
    if (c->kind == 7 || c->kind == 13) {
      mrdv_put_hex((u64)c->fin);
      mrdv_put("|");
    }
  }
  mrdv_text[mrdv_at] = 0;
  return mrdv_text;
}

static int mups_up_is(u64 sid, const char* want) {
  const char* got = mups_up_log(sid);
  usz         i   = 0;
  while (got[i] && got[i] == want[i]) i++;
  if (got[i] != want[i]) printf("  up got \"%s\" want \"%s\"\n", got, want);
  return got[i] == want[i];
}

/* U1 NoOkBeforeUpstream (9.4/7.4): B's SUBSCRIBE goes upstream as a
 * SUBSCRIBE in A's draft with the server's odd Request ID (10.1) and no
 * parameters (FORWARD defaults to 1, unfiltered); B hears nothing until
 * A's SUBSCRIBE_OK, then SUBSCRIBE_OK, and B is an active subscriber of
 * the track A's alias now names. */
static void test_moqtrun_upsub_ok_after_upstream(void) {
  moqctl_subscribe m;
  moqctl_ftn       f = mrdv_f();
  i64              sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  sid = mups_up(SESS_A, 0, &m);
  CHECK(sid >= 0);
  CHECK((m.request_id & 1) == 1);
  CHECK(m.params.n == 0);
  CHECK(m.name.name.n == f.name.n);
  CHECK(m.name.ns.n == 2);
  mups_ok((u64)sid);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  CHECK(mrdv_alias(SESS_B, MRDV_S1) == mtst_sub(SESS_A, SESS_B)->track_alias);
  CHECK(mrdv_used() == 0);
  CHECK(mups_used() == 1);
}

/* Header (Type 0x30, alias, Group 0) + one Object. */
static usz mups_stream(u64 alias, u8* buf) {
  moqdata_subhdr h   = {0};
  usz            off = 0;
  u8             b   = 0x5a;
  wired_mspan    out = wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD);
  h.type             = 0x30;
  h.track_alias      = alias;
  moqdata_subhdr_put(out, &off, &h);
  moqdata_obj_put(out, &off, 0, wired_span_of(&b, 1));
  return off;
}

/* Track Alias of the last uni stream the hub sent s; ~0 if none. */
static u64 mups_relayed_alias(wired_wt_session* s) {
  u64 alias = ~(u64)0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0;
    moqdata_subhdr           h;
    if (c->s != s || (c->kind != 4 && c->kind != 5)) continue;
    if (moqdata_subhdr_take(
            wired_span_of(c->payload, c->payload_len), &off, &h) == MOQDATA_OK)
      alias = h.track_alias;
  }
  return alias;
}

/* U2 (9.4 "Relays use the Track Alias of an incoming Object"): A's
 * SUBGROUP stream under the alias its SUBSCRIBE_OK named reaches B under
 * B's own alias (moqtrun_alias_splice). */
static void test_moqtrun_upsub_objects_relayed(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mups_ok((u64)mups_up_sid());
  n = mups_stream(MUPS_ALIAS, buf);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MUPS_DATA_SID, wired_span_of(buf, n), 1);
  CHECK(mups_relayed_alias(SESS_B) == mrdv_alias(SESS_B, MRDV_S1));
}

/* U3 aggregation (9.4 MAY): B and C waiting share one upstream SUBSCRIBE
 * and both get SUBSCRIBE_OK; D arriving once it is Established is
 * answered at once, still with one upstream. */
static void test_moqtrun_upsub_two_share_one(void) {
  mups_init();
  mtst_join(SESS_C);
  mtst_join(SESS_D);
  mups_sub(SESS_B, MRDV_S1);
  mups_sub(SESS_C, MRDV_S1);
  CHECK(mups_n_up(SESS_A) == 1);
  mups_ok((u64)mups_up_sid());
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|"));
  mups_sub(SESS_D, MRDV_S1);
  CHECK(mrdv_is(SESS_D, MRDV_S1, "SOK|"));
  CHECK(mups_n_up(SESS_A) == 1);
}

/* U4 UpErr: A's REQUEST_ERROR reaches every waiter with its code; the
 * hub ends its side of the upstream stream and forgets the entry. */
static void test_moqtrun_upsub_error_relayed(void) {
  u64 sid;
  mups_init();
  mtst_join(SESS_C);
  mups_sub(SESS_B, MRDV_S1);
  mups_sub(SESS_C, MRDV_S1);
  sid = (u64)mups_up_sid();
  mtst_pub_err(SESS_A, sid, MOQCTL_ERR_UNAUTHORIZED);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E1|FIN|"));
  CHECK(mrdv_is(SESS_C, MRDV_S1, "E1|FIN|"));
  CHECK(mups_up_is(sid, "FIN|"));
  CHECK(mups_used() == 0);
  CHECK(mrdv_used() == 0);
}

/* U5 NoLeak: the upstream outlives one downstream cancel, and is
 * cancelled (RESET_STREAM + STOP_SENDING CANCELLED, 19 3.3.3) with the
 * last; A's track goes with it. */
static void test_moqtrun_upsub_last_cancel_cancels_upstream(void) {
  u64 sid;
  mups_init();
  mtst_join(SESS_C);
  mups_sub(SESS_B, MRDV_S1);
  mups_sub(SESS_C, MRDV_S1);
  sid = (u64)mups_up_sid();
  mups_ok(sid);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MRDV_S1, 0, 0);
  CHECK(mups_up_is(sid, ""));
  wired_moqt_on_stream_reset(&mtst_hub, SESS_C, MRDV_S1, 0, 0);
  CHECK(mups_up_is(sid, "RST1|STOP1|"));
  CHECK(mups_used() == 0);
  CHECK(!moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].in_use);
}

/* U6 NoLeak (pending) + stale reply: the only waiter cancels before the
 * answer -- the upstream is cancelled, and A's late SUBSCRIBE_OK on that
 * stream claims nothing and answers no one. */
static void test_moqtrun_upsub_pending_cancel_and_stale_ok(void) {
  u64 sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MRDV_S1, 0, 0);
  CHECK(mups_up_is(sid, "RST1|STOP1|"));
  CHECK(mups_used() == 0);
  mups_ok(sid);
  CHECK(!moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].in_use);
  CHECK(!moqtrun_find_by_wt(&mtst_hub, SESS_A)->closing);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "RST1|"));
}

/* U7 (10.11 relayed): A's PUBLISH_DONE on the upstream stream reaches B
 * as PUBLISH_DONE on B's stream; the hub then ends its upstream side. */
static void test_moqtrun_upsub_publish_done_relayed(void) {
  u64 sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  mups_ok(sid);
  mups_done(sid, MOQCTL_DONE_TRACK_ENDED);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|Tb|FIN|"));
  CHECK(mups_up_is(sid, "FIN|"));
  CHECK(mups_used() == 0);
}

/* U8 NoLeakOnClose: A's session closing frees its entries with no io; a
 * waiter left with no announcer gets DOES_NOT_EXIST, an Established
 * subscriber its PUBLISH_DONE (TRACK_ENDED). */
static void test_moqtrun_upsub_publisher_close(void) {
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E10|FIN|"));
  CHECK(mups_used() == 0);
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mups_ok((u64)mups_up_sid());
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|Tb|FIN|"));
  CHECK(mups_used() == 0);
}

/* U9 (9.5 "a PUBLISH_NAMESPACE ... MUST send a SUBSCRIBE"; interop
 * subscribe-before-announce): a rendezvous hold made before any
 * announcer goes upstream once A announces, and resolves on its OK. */
static void test_moqtrun_upsub_hold_then_announce(void) {
  mrdv_init();
  mups_sids();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  CHECK(mups_n_up(SESS_A) == 0);
  mups_announce();
  CHECK(mups_n_up(SESS_A) == 1);
  mups_ok((u64)mups_up_sid());
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  wired_moqt_tick(&mtst_hub, 600);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
}

/* U10: no stream to open toward the publisher (the QUIC stream limit is
 * MOQT's request limit since draft-18 removed MAX_REQUEST_ID) -- the
 * SUBSCRIBE is refused EXCESSIVE_LOAD now, nothing is held. */
static void test_moqtrun_upsub_open_fails(void) {
  mups_init();
  g_open_bidi_fail_n = 1;
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E9|FIN|"));
  CHECK(mups_used() == 0);
  CHECK(mrdv_used() == 0);
}

/* U11: a session's own announcement never routes its SUBSCRIBE back to
 * itself; with no other announcer it is DOES_NOT_EXIST at once. */
static void test_moqtrun_upsub_own_namespace(void) {
  mrdv_init();
  mtns_pub(SESS_B, MRDV_S2, "chat/room1");
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E10|FIN|"));
  CHECK(mups_n_up(SESS_B) == 0);
}

/* U12 prefix matching (9.5): an announcement of the namespace's first
 * field alone covers it; an unrelated one does not. */
static void test_moqtrun_upsub_prefix(void) {
  mrdv_init();
  mtns_pub(SESS_A, MRDV_S1, "other");
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E10|FIN|"));
  mtns_pub(SESS_A, MRDV_S2, "chat");
  mups_sub(SESS_B, MRDV_S2);
  CHECK(mups_n_up(SESS_A) == 1);
}

static void mtall_upsub(void) {
  test_moqtrun_upsub_ok_after_upstream();
  test_moqtrun_upsub_objects_relayed();
  test_moqtrun_upsub_two_share_one();
  test_moqtrun_upsub_error_relayed();
  test_moqtrun_upsub_last_cancel_cancels_upstream();
  test_moqtrun_upsub_pending_cancel_and_stale_ok();
  test_moqtrun_upsub_publish_done_relayed();
  test_moqtrun_upsub_publisher_close();
  test_moqtrun_upsub_hold_then_announce();
  test_moqtrun_upsub_open_fails();
  test_moqtrun_upsub_own_namespace();
  test_moqtrun_upsub_prefix();
}

/* Cross-draft: A's reply decoded in A's draft, B's answer spelled in B's
 * (a d19/22 CONFLICTING_FILTERS reaches a d18 subscriber as d18's
 * EXCESSIVE_LOAD, moqctl_request_error_for). */
static void mups_xver(int pv, int sv) {
  u64 sid;
  mups_init_v(pv, sv);
  mups_sub(SESS_B, MRDV_S1);
  mups_ok((u64)mups_up_sid());
  CHECK(mrdv_alias(SESS_B, MRDV_S1) == mtst_sub(SESS_A, SESS_B)->track_alias);
  mups_init_v(pv, sv);
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  mtst_pub_err(SESS_A, sid, MOQCTL_ERR_CONFLICTING_FILTERS);
  CHECK(
      mrdv_err(SESS_B, MRDV_S1).error_code ==
      moqctl_request_error_for(sv, MOQCTL_ERR_CONFLICTING_FILTERS));
}

static void test_moqtrun_upsub_cross_draft(void) {
  for (int pv = 0; pv < MOQVER_COUNT; pv++)
    for (int sv = 0; sv < MOQVER_COUNT; sv++) {
      int fails = wired_test_fails;
      mups_xver(pv, sv);
      if (wired_test_fails != fails) printf("  ^ pub %d sub %d\n", pv, sv);
    }
}

void test_moqtrun_upsub(void) {
  moqtrun_test_allver(mtall_upsub);
  test_moqtrun_upsub_cross_draft();
}
