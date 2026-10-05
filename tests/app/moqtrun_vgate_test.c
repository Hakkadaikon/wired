/* Per-draft gates of the hub (draft-ietf-moq-transport-18/19/22): a
 * behavior one draft defines and another does not is keyed on the peer's
 * negotiated draft. Shares the recording io stubs (moqtrun_test.c) and the
 * request-stream / update fixtures (moqtrun_sub_test.c, moqtrun_upd_test.c,
 * moqtrun_subtracks_test.c) of the same unity TU. */

/* Number of REQUEST_OK messages the transport accepted on sid (coalesced
 * replies share one stream_send, so every message is walked). */
static usz mtvg_oks_on(u64 sid) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    if ((c->kind != 3 && c->kind != 12) || c->stream_id != sid) continue;
    if (c->refused) continue;
    usz        off = 0;
    u64        t;
    wired_span body;
    wired_span all = wired_span_of(c->payload, c->payload_len);
    while (moqctl_peek_type(all, &off, &t, &body) == MOQCTL_OK)
      n += t == MOQCTL_T_REQUEST_OK;
  }
  return n;
}

/* MAX_REQUEST_UPDATES + 1 REQUEST_UPDATEs on B's subscription stream while
 * the transport takes no replies, so none is answered yet. */
static void mtvg_pipeline_updates(void) {
  moqctl_params p1 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  moqctl_ftn    f  = mtup_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  moqtrun_test_reset();
  g_stream_send_ok_n = 0;
  for (usz i = 0; i <= WIRED_MOQTRUN_MAX_REQ_UPDATES; i++)
    mtup_update(SESS_B, MTRQ_S1, &p1);
}

/* 12-5, draft-19 10.3.1.7 / draft-22 9.1.7: "If an endpoint receives a
 * REQUEST_UPDATE on a stream that already has MAX_REQUEST_UPDATES
 * outstanding REQUEST_UPDATEs, it MUST close the session with
 * TOO_MANY_REQUEST_UPDATES." */
static void mtvg_credit_closes(void) {
  mtvg_pipeline_updates();
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 1);
  g_stream_send_ok_n = -1;
}

/* 12-5, draft-18 10.9 has no MAX_REQUEST_UPDATES (and the hub's draft-18
 * SETUP advertises none): the same pipeline is not closed, and every
 * update still gets its own REQUEST_OK once the transport drains
 * (10.9.1: "MUST still send a REQUEST_OK for each successful update"). */
static void mtvg_credit_unlimited(void) {
  mtvg_pipeline_updates();
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 0);
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mtvg_oks_on(MTRQ_S1) == WIRED_MOQTRUN_MAX_REQ_UPDATES + 1);
}

static void test_moqtrun_vgate_update_credit(void) {
  moqtrun_test_vers(MOQVER_CAP_MAX_REQUEST_UPDATES, 0, mtvg_credit_closes);
  moqtrun_test_vers(0, MOQVER_CAP_MAX_REQUEST_UPDATES, mtvg_credit_unlimited);
}

/* 12-6, draft-18/19 10.9 and draft-22 9.5, verbatim in all three: "The
 * sender of a request (SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE,
 * SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS) can later send a REQUEST_UPDATE
 * on the same bidi stream as the request to modify it." A publisher's
 * update of its own PUBLISH is answered REQUEST_OK on every draft. */
static void mtvg_update_own_publish(void) {
  static const u8 upd[] = {0x04, 0x00}; /* Request ID 4, no parameters */
  moqctl_ftn      f     = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  mtst_join(SESS_A);
  mtst_publish(SESS_A, MTRQ_S1, &f, 1);
  mtrq_raw(SESS_A, MTRQ_S1, MOQTSTAT_T_REQUEST_UPDATE, upd, sizeof upd);
  CHECK(mtup_reply(MTRQ_S1, &(wired_span){0, 0}) == MOQCTL_T_REQUEST_OK);
  CHECK(mtst_hub.peers[0].tracks[0].in_use == 1);
}

/* 12-6: an update of a SUBSCRIBE_TRACKS is one of the allowed cases, so
 * it is answered (10.9: "MUST respond with exactly one REQUEST_OK or
 * REQUEST_ERROR") and never closes the session; this hub refuses it with
 * NOT_SUPPORTED on every draft and the request stays established. */
static void mtvg_update_subtracks(void) {
  moqctl_params p1 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  mtst_init();
  mtst_join(SESS_B);
  mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  mtup_update(SESS_B, MTRQ_S1, &p1);
  CHECK(mtup_err_code(MTRQ_S1) == MOQCTL_ERR_NOT_SUPPORTED);
  CHECK(mtrq_closes() == 0);
  CHECK(mtrq_used() == 1);
}

static void test_moqtrun_vgate_update_kinds(void) {
  moqtrun_test_vers(0, 0, mtvg_update_own_publish);
  moqtrun_test_vers(0, 0, mtvg_update_subtracks);
}

/* A publishes chat/room1/alice; then B sends SUBSCRIBE_TRACKS "chat"
 * carrying FORWARD 0 and, when go is non-zero, GROUP_ORDER go. */
static void mtvg_subtracks_then_publish(u8 go) {
  static moqns_req m;
  moqctl_ftn       f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  moqtrun_test_reset();
  m.request_id           = mtst_rid += 2;
  m.ns                   = mtns_ns("chat");
  m.params               = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  m.params.items[1].type = MOQCTL_PARAM_GROUP_ORDER;
  m.params.items[1].enc  = MOQCTL_PENC_UINT8;
  m.params.items[1].u8v  = go;
  m.params.n += go != 0;
  mtst_send(SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE_TRACKS, mtst_enc_subtracks, &m);
}

/* The hub's PUBLISH to B, per draft-18/19 10.10 and draft-22 9.8 (one
 * layout in all three): Type 0x1D, Length (16), Request ID, Track
 * Namespace (2 fields "chat" "room1"), Track Name "alice", Track Alias,
 * Number of Parameters, then FORWARD (Type 0x10, uint8 0) and GROUP_ORDER
 * (Type Delta 0x22-0x10 = 0x12, uint8 go), no Track Properties. Request ID
 * and Alias are the hub's own picks (each a 1-byte varint here). */
static usz mtvg_publish_wire(u8* w, u8 go) {
  static const u8 name[] = {0x02, 0x04, 'c', 'h',  'a', 't', 0x05, 'r', 'o',
                            'o',  'm',  '1', 0x05, 'a', 'l', 'i',  'c', 'e'};
  const wired_moqtrun_req* q = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (mtst_hub.reqs[i].in_use && mtst_hub.reqs[i].pub_origin_rid)
      q = &mtst_hub.reqs[i];
  CHECK(q != 0);
  if (!q) return 0;
  CHECK(q->request_id < 64);
  CHECK(mtst_hub.peers[0].tracks[0].own_alias < 64);
  usz n  = 3;
  w[n++] = (u8)q->request_id;
  bytes_memcpy(w + n, name, sizeof name);
  n += sizeof name;
  w[n++] = (u8)mtst_hub.peers[0].tracks[0].own_alias;
  w[n++] = go ? 2 : 1;
  w[n++] = 0x10;
  w[n++] = 0x00;
  if (go) w[n++] = 0x12;
  if (go) w[n++] = go;
  w[0] = MOQCTL_T_PUBLISH;
  w[1] = 0;
  w[2] = (u8)(n - 3);
  return n;
}

/* 12-7: the PUBLISH opened to B is exactly the pinned bytes, and B's own
 * draft decodes it whole (moqctl_publish_take with B's version). */
static void mtvg_hub_publish_in(u8 go) {
  u8             want[64];
  moqctl_publish got;
  usz            off = 0, boff = 0;
  u64            t;
  wired_span     body;
  mtvg_subtracks_then_publish(go);
  const moqtrun_test_call* c = moqtrun_test_last_kind(1);
  usz                      n = mtvg_publish_wire(want, go);
  CHECK(c != 0);
  if (!c) return;
  CHECK(c->s == SESS_B && c->payload_len == n);
  CHECK(c->payload_len == n && !ct_diffn(c->payload, want, n));
  wired_span all = wired_span_of(c->payload, c->payload_len);
  CHECK(moqctl_peek_type(all, &off, &t, &body) == MOQCTL_OK);
  int r = moqctl_publish_take(g_moqtrun_test_ver, body, &boff, &got);
  CHECK(moqctl_body_end(r, boff, body) == MOQCTL_OK);
}

static void mtvg_hub_publish_forward0(void) { mtvg_hub_publish_in(0); }

/* GROUP_ORDER rides SUBSCRIBE_TRACKS from draft-19 on (19 10.2.8, 22
 * 9.20.8) and is echoed into the PUBLISH ("PUBLISH messages resulting
 * from this SUBSCRIBE_TRACKS will include the GROUP_ORDER parameter with
 * the same value", 19 10.19.1; 22 3.6.2). draft-18 10.2.8 does not admit
 * it on SUBSCRIBE_TRACKS, so a draft-18 PUBLISH never carries it. */
static void test_moqtrun_vgate_hub_publish(void) {
  static const int vers[] = {MOQVER_D19, MOQVER_D22};
  moqtrun_test_vers(0, 0, mtvg_hub_publish_forward0);
  for (usz v = 0; v < 2; v++) {
    g_moqtrun_test_ver = vers[v];
    mtvg_hub_publish_in(2);
  }
  g_moqtrun_test_ver = MOQVER_D19;
}

void test_moqtrun_vgate(void) {
  test_moqtrun_vgate_update_credit();
  test_moqtrun_vgate_update_kinds();
  test_moqtrun_vgate_hub_publish();
}
