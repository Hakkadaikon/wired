/* Cross-version hub behavior (draft-ietf-moq-transport-18/19/22): what
 * the hub encodes for one peer follows THAT peer's negotiated draft.
 * Shares the recording io stubs (moqtrun_test.c) and the subscription
 * fixtures (moqtrun_sub_test.c) of the same unity TU. */

/* ===================== SETUP options per draft ===================== */

/* The hub's SETUP to a peer that negotiated tok, decoded; 1 iff found. */
static int mtxv_setup_of(const char* tok, moqctl_setup* s) {
  wired_moqt_hub hub;
  usz            off = 0, boff = 0;
  u64            type;
  wired_span     body;
  moqtrun_test_reset();
  wired_moqt_init(&hub, moqtrun_test_io());
  wired_moqt_on_session(
      &hub, SESS_A, wired_span_of(0, 0), moqtrun_test_proto(tok));
  const moqtrun_test_call* c = moqtrun_test_last_kind(5);
  if (!c) return 0;
  moqctl_peek_type(
      wired_span_of(c->payload, c->payload_len), &off, &type, &body);
  return moqctl_setup_take(body, &boff, s) == MOQCTL_OK;
}

/* draft-18 10.3.1 has no MAX_FILTER_RANGES (0x06) / MAX_REQUEST_UPDATES
 * (0x08) Setup Options: a draft-18 SETUP omits both. */
static void test_moqtrun_xver_setup_d18_omits_d19_options(void) {
  moqctl_setup s = {0};
  CHECK(mtxv_setup_of("moqt-18", &s));
  CHECK(s.max_filter_ranges == 0);
  CHECK(s.max_request_updates == 0);
}

/* draft-19 10.4 / draft-22: both limits are still advertised. */
static void test_moqtrun_xver_setup_d19_d22_carry_options(void) {
  moqctl_setup s = {0};
  CHECK(mtxv_setup_of("moqt-19", &s));
  CHECK(s.max_filter_ranges == WIRED_MOQTRUN_MAX_FILTER_RANGES);
  CHECK(s.max_request_updates == WIRED_MOQTRUN_MAX_REQ_UPDATES);
  CHECK(mtxv_setup_of("moqt-22", &s));
  CHECK(s.max_filter_ranges == WIRED_MOQTRUN_MAX_FILTER_RANGES);
  CHECK(s.max_request_updates == WIRED_MOQTRUN_MAX_REQ_UPDATES);
}

/* ===================== relay across drafts ===================== */

/* Publisher A on draft pv, subscriber B on draft sv; cap > 0 attaches
 * the FETCH cache. A PUBLISHes alice (alias MF_ALIAS) after both drafts
 * are fixed, so every control message is taken in its sender's draft. */
static void mtxv_init(int pv, int sv, usz cap) {
  moqctl_ftn f = mf_track();
  mtst_init();
  if (cap) wired_moqt_cache_attach(&mtst_hub, mf_arena, cap);
  mf_pub_sid                                 = 2;
  mf_ctrl_a                                  = mtst_join(SESS_A);
  mf_ctrl_b                                  = mtst_join(SESS_B);
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->ver = pv;
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = sv;
  mtst_publish(SESS_A, mf_ctrl_a, &f, MF_ALIAS);
}

/* The last control message the hub sent to s (control or request
 * stream) of Type type: its body, 0-length when there is none. */
static wired_span mtxv_last_body(wired_wt_session* s, u64 type) {
  for (usz i = g_n_calls; i-- > 0;) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0;
    u64                      t   = 0;
    wired_span               body;
    if (c->s != s || (c->kind != 3 && c->kind != 12)) continue;
    moqctl_peek_type(
        wired_span_of(c->payload, c->payload_len), &off, &t, &body);
    if (t == type) return body;
  }
  return wired_span_of(0, 0);
}

/* B's SUBSCRIBE_OK decodes, whole, in B's own draft sv and names B's
 * subscription alias. */
static int mtxv_sub_ok_in(int sv) {
  moqctl_subscribe_ok ok;
  usz                 off  = 0;
  wired_span          body = mtxv_last_body(SESS_B, MOQCTL_T_SUBSCRIBE_OK);
  int                 r    = moqctl_subscribe_ok_take(sv, body, &off, &ok);
  return moqctl_body_end(r, off, body) == MOQCTL_OK &&
         ok.track_alias == mtst_sub(SESS_A, SESS_B)->track_alias;
}

/* 1 iff the only relay call to B of io kind is exactly bytes[0..n). */
static int mtxv_relayed_as(int kind, const u8* bytes, usz n) {
  const moqtrun_test_call* c = moqtrun_test_last_kind(kind);
  if (moqtrun_test_count_kind(kind) != 1 || c->s != SESS_B) return 0;
  return c->payload_len == n && !ct_diffn(c->payload, bytes, n);
}

/* 5-1 / draft-18,19,22 SS11: SUBGROUP streams and OBJECT_DATAGRAMs are
 * byte-identical across the drafts, so A's bytes reach B verbatim
 * whatever the two negotiated; B's SUBSCRIBE_OK is in B's draft. */
static void mtxv_relay_pair(int pv, int sv) {
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_ftn f = mf_track();
  mtxv_init(pv, sv, 0);
  mtst_subscribe(SESS_B, mf_ctrl_b, &f);
  CHECK(mtxv_sub_ok_in(sv));
  usz n = mtst_stream(3, 2, 1, buf);
  moqtrun_test_reset();
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 1);
  CHECK(mtxv_relayed_as(4, buf, n));
  moqtrun_test_reset();
  wired_moqt_on_datagram(
      &mtst_hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
  CHECK(mtxv_relayed_as(9, MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
}

static void test_moqtrun_xver_relay_pub18_sub22(void) {
  mtxv_relay_pair(MOQVER_D18, MOQVER_D22);
}

static void test_moqtrun_xver_relay_pub22_sub18(void) {
  mtxv_relay_pair(MOQVER_D22, MOQVER_D18);
}

static void test_moqtrun_xver_relay_pub19_sub22(void) {
  mtxv_relay_pair(MOQVER_D19, MOQVER_D22);
}

/* The hub's GOAWAY to s decodes, whole, with take; its Request ID. */
static int mtxv_goaway_as(
    wired_wt_session* s,
    int (*take)(wired_span, usz*, moqctl_goaway*),
    u64* rid) {
  moqctl_goaway g   = {0};
  usz           off = 0;
  wired_span    b   = mtxv_last_body(s, MOQCTL_T_GOAWAY);
  int           r   = b.n ? take(b, &off, &g) : MOQCTL_INSUFFICIENT;
  *rid              = g.request_id;
  return moqctl_body_end(r, off, b) == MOQCTL_OK;
}

/* One hub-wide GOAWAY is encoded per destination: draft-18 SS10.4 ends
 * the control-stream GOAWAY with the peer's next Request ID; the
 * draft-22 publisher's (SS9.2) has no such field -- whatever the draft
 * of the other side of the relay. */
static void test_moqtrun_xver_goaway_per_destination(void) {
  moqctl_ftn f = mf_track();
  u64        rid;
  mtxv_init(MOQVER_D22, MOQVER_D18, 0);
  mtst_subscribe(SESS_B, mf_ctrl_b, &f);
  wired_moqt_goaway(&mtst_hub, wired_span_of(0, 0), 0);
  CHECK(mtxv_goaway_as(SESS_B, moqctl_goaway18_take, &rid));
  CHECK(rid == moqtrun_find_by_wt(&mtst_hub, SESS_B)->peer_rid_next);
  CHECK(mtxv_goaway_as(SESS_A, moqctl_goaway_take, &rid));
  CHECK(!mtxv_goaway_as(SESS_A, moqctl_goaway18_take, &rid));
}

/* draft-22 SS9.20.9: a draft-22 subscriber's typed LOCATION_FILTER
 * (0x02 Absolute Start) resolves against a draft-18 publisher's track;
 * a draft-18 subscriber's untyped Largest Object filter (10.2.4)
 * resolves against a draft-22 publisher's -- Largest {3,1} here. */
static void test_moqtrun_xver_location_filter_each_draft(void) {
  u8            buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_ftn    f = mf_track();
  moqctl_params p =
      mt22_filter(1, mt22_rl(MOQCTL_RSK_ABS, 2, 1, MOQCTL_REK_UNBOUNDED, 0, 0));
  moqctl_params lo = mtst_params_filter(MOQCTL_FILTER_LARGEST);
  usz           n  = mtst_stream(3, 2, 1, buf);
  mtxv_init(MOQVER_D18, MOQVER_D22, 0);
  mtst_subscribe_p(SESS_B, mf_ctrl_b, &f, 2, &p);
  CHECK(mtxv_sub_ok_in(MOQVER_D22));
  CHECK(mf_loc_eq(mtst_sub(SESS_A, SESS_B)->start, 2, 1));
  mtxv_init(MOQVER_D22, MOQVER_D18, 0);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 1);
  mtst_subscribe_p(SESS_B, mf_ctrl_b, &f, 2, &lo);
  CHECK(mtxv_sub_ok_in(MOQVER_D18));
  CHECK(mf_loc_eq(mtst_sub(SESS_A, SESS_B)->start, 3, 2));
}

/* 5-3: the FETCH cache re-encodes per request in the REQUESTER's draft
 * -- a draft-22 FETCH of a draft-18 publisher's Objects is answered
 * with draft-22's inclusive End Location (SS9.12), a draft-19 one with
 * draft-19's exclusive one (10.13) -- and the Objects (11.4.4, the same
 * bytes in every draft) carry the publisher's payloads. */
static void test_moqtrun_xver_fetch_in_requester_draft(void) {
  moqfetch_ok ok;
  mtxv_init(MOQVER_D18, MOQVER_D22, sizeof mf_arena);
  mf_obj(0, 0, 3);
  mf_obj(0, 1, 2);
  mf_fetch22(0);
  CHECK(
      moqfetch_ok_take(
          MOQVER_D22, mtxv_last_body(SESS_B, MOQFETCH_T_FETCH_OK), &ok) ==
      MOQCTL_OK);
  CHECK(mf_loc_eq(ok.end, 0, 1));
  CHECK(mf_read());
  CHECK(mf_n == 2 && mf_is_obj(0, 0, 0, 3) && mf_is_obj(1, 0, 1, 2));
  mtxv_init(MOQVER_D22, MOQVER_D19, sizeof mf_arena);
  mf_obj(0, 0, 3);
  mf_obj(0, 1, 2);
  mf_standalone(mf_loc(0, 0), mf_loc(0, 2));
  CHECK(mf_loc_eq(mf_ok_end(), 0, 2));
  CHECK(mf_read());
  CHECK(mf_n == 2 && mf_is_obj(0, 0, 0, 3) && mf_is_obj(1, 0, 1, 2));
}

/* A draft-19 subscriber's Joining FETCH (10.12.2) is served from the
 * hub's own cache, never forwarded to the draft-22 publisher (whose
 * draft has no Joining FETCH): nothing goes to A. */
static void test_moqtrun_xver_joining_d19_sub_of_d22_pub(void) {
  mtxv_init(MOQVER_D22, MOQVER_D19, sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  u64 rid = mf_subscribe(0);
  moqtrun_test_reset();
  mf_joining(MOQFETCH_RELATIVE_JOINING, rid, 1);
  CHECK(mf_loc_eq(mf_ok_end(), 1, 1));
  CHECK(mf_read());
  CHECK(mf_n == 2 && mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 1, 0, 1));
  for (usz i = 0; i < g_n_calls; i++) CHECK(g_calls[i].s != SESS_A);
}

void test_moqtrun_xver(void) {
  test_moqtrun_xver_setup_d18_omits_d19_options();
  test_moqtrun_xver_setup_d19_d22_carry_options();
  test_moqtrun_xver_relay_pub18_sub22();
  test_moqtrun_xver_relay_pub22_sub18();
  test_moqtrun_xver_relay_pub19_sub22();
  test_moqtrun_xver_goaway_per_destination();
  test_moqtrun_xver_location_filter_each_draft();
  test_moqtrun_xver_fetch_in_requester_draft();
  test_moqtrun_xver_joining_d19_sub_of_d22_pub();
}
