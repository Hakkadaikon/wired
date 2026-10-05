/* Hub-opened PUBLISH subscriptions and stray REQUEST_UPDATEs (ledger
 * 12-11/12-17/12-18/12-19; draft-ietf-moq-transport-18/19 10.9/10.19,
 * draft-22 3.6.2/9.5/9.8). Shares the recording io stubs (moqtrun_test.c)
 * and the request-stream / update / SUBSCRIBE_TRACKS fixtures
 * (moqtrun_sub_test.c, moqtrun_upd_test.c, moqtrun_subtracks_test.c) of
 * the same unity TU. */

/* Track Alias of the last Object stream relayed (send_uni) to s; ~0 if
 * none. */
static u64 mtmi_relayed_alias(wired_wt_session* s) {
  for (usz i = g_n_calls; i > 0; i--) {
    const moqtrun_test_call* c   = &g_calls[i - 1];
    usz                      off = 0;
    moqdata_subhdr           h;
    if (c->kind != 4 || c->s != s) continue;
    if (moqdata_subhdr_take(
            wired_span_of(c->payload, c->payload_len), &off, &h) != MOQDATA_OK)
      return ~(u64)0;
    return h.track_alias;
  }
  return ~(u64)0;
}

/* A publishes chat/room1/alice (alias 1) on its control stream, B sends
 * SUBSCRIBE_TRACKS "chat" (FORWARD 0 when fwd0); *pub is the hub's PUBLISH
 * to B, the return its stream id. */
static u64 mtmi_setup(int fwd0, moqctl_publish* pub) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  if (fwd0) mtst_subtracks_fwd0(SESS_B, MTRQ_S1, "chat");
  if (!fwd0) mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  CHECK(mtst_pub_opens(SESS_B, pub, 1) == 1);
  i64 sid = mtst_pub_stream_id(0);
  CHECK(sid >= 0);
  return (u64)sid;
}

/* A sends Group g (one Object, one-shot stream). */
static void mtmi_object(u64 g, u64 sid) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = mtst_stream(g, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, sid, wired_span_of(buf, n), 1);
}

/* 12-11, d18/d19 10.19 + 10.10, d22 3.6/9.8: the PUBLISH_OK (REQUEST_OK)
 * of a SUBSCRIBE_TRACKS-generated PUBLISH establishes a subscription, so
 * the track's Objects reach the subscriber under the PUBLISH's alias. */
static void test_moqtrun_misc_pub_ok_relays(void) {
  moqctl_publish pub;
  u64            sid = mtmi_setup(0, &pub);
  mtst_pub_ok(SESS_B, sid);
  moqtrun_test_reset();
  mtmi_object(3, 2001);
  CHECK(mtmi_relayed_alias(SESS_B) == pub.track_alias);
}

/* 12-11: FORWARD 0 carried by the PUBLISH (10.19.1/T-12) holds Objects
 * back after PUBLISH_OK (d18 SS5 "The publisher does not send Objects if
 * the Forward State is 0"); 12-18: the subscriber's REQUEST_UPDATE
 * FORWARD 1 on the PUBLISH stream ("A subscriber can also send
 * REQUEST_UPDATE to modify parameters of a subscription established with
 * PUBLISH", d18/d19 10.9, d22 9.5) is answered REQUEST_OK there and
 * Objects then flow. */
static void test_moqtrun_misc_pub_forward0_then_update(void) {
  moqctl_params  p1 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  moqctl_publish pub;
  u64            sid = mtmi_setup(1, &pub);
  mtst_pub_ok(SESS_B, sid);
  moqtrun_test_reset();
  mtmi_object(3, 2001);
  CHECK(mtmi_relayed_alias(SESS_B) == ~(u64)0);
  mtup_update(SESS_B, sid, &p1);
  CHECK(mtup_reply(sid, &(wired_span){0, 0}) == MOQCTL_T_REQUEST_OK);
  mtmi_object(4, 2005);
  CHECK(mtmi_relayed_alias(SESS_B) == pub.track_alias);
  CHECK(mtrq_closes() == 0);
}

/* 12-18: "MUST respond with exactly one REQUEST_OK or REQUEST_ERROR"
 * (d18/d19 10.9; d22 9.5 REQUEST_UPDATE_OK/ERROR) -- an update before the
 * PUBLISH_OK has no subscription to modify and is refused, not dropped. */
static void test_moqtrun_misc_pub_update_before_ok(void) {
  moqctl_params  p1 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  moqctl_publish pub;
  u64            sid = mtmi_setup(0, &pub);
  mtup_update(SESS_B, sid, &p1);
  CHECK(mtup_err_code(sid) == MOQCTL_ERR_DOES_NOT_EXIST);
  CHECK(mtrq_closes() == 0);
}

static void mtall_misc(void) {
  test_moqtrun_misc_pub_ok_relays();
  test_moqtrun_misc_pub_forward0_then_update();
  test_moqtrun_misc_pub_update_before_ok();
}

/* 12-17, d19 10.9 / d22 9.5: "An endpoint that receives a REQUEST_UPDATE
 * other than in the two cases above MUST close the session with a
 * PROTOCOL_VIOLATION" -- one on the control stream updates no request. */
static void mtmi_update_on_ctl_closes(void) {
  moqctl_params p1 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  mtst_init();
  u64 cb = mtst_join(SESS_B);
  mtup_update(SESS_B, cb, &p1);
  CHECK(mtrq_closes() == 1);
}

/* 12-17, d18 10.9 has no such sentence (only "MUST respond with exactly
 * one REQUEST_OK or REQUEST_ERROR"): the hub keeps answering
 * NOT_SUPPORTED and the session stays up. */
static void mtmi_update_on_ctl_refused(void) {
  moqctl_params p1 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  mtst_init();
  u64 cb = mtst_join(SESS_B);
  mtup_update(SESS_B, cb, &p1);
  CHECK(mtrq_closes() == 0);
  CHECK(mtrq_err_on(cb) == MOQCTL_ERR_NOT_SUPPORTED);
}

/* 12-17: TRACK_STATUS is not in 10.9's list of updatable requests either. */
static void mtmi_update_on_tstat_closes(void) {
  moqctl_params p1 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  moqctl_ftn    f  = mtrq_setup();
  mtup_tstat(SESS_B, MTRQ_S1, &f);
  mtup_update(SESS_B, MTRQ_S1, &p1);
  CHECK(mtrq_closes() == 1);
}

static void test_moqtrun_misc_stray_update(void) {
  moqtrun_test_vers(
      MOQVER_CAP_UPDATE_STRAY_CLOSE, 0, mtmi_update_on_ctl_closes);
  moqtrun_test_vers(
      0, MOQVER_CAP_UPDATE_STRAY_CLOSE, mtmi_update_on_ctl_refused);
  moqtrun_test_vers(
      MOQVER_CAP_UPDATE_STRAY_CLOSE, 0, mtmi_update_on_tstat_closes);
}

/* B's SUBSCRIBE_TRACKS "chat" carrying FORWARD 1 and GROUP_ORDER 2, after A
 * published chat/room1/alice. */
static void mtmi_subtracks_fwd1_go2(void) {
  static moqns_req m;
  moqctl_ftn       f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  moqtrun_test_reset();
  m.request_id           = mtst_rid += 2;
  m.ns                   = mtns_ns("chat");
  m.params               = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  m.params.items[1].type = MOQCTL_PARAM_GROUP_ORDER;
  m.params.items[1].enc  = MOQCTL_PENC_UINT8;
  m.params.items[1].u8v  = 2;
  m.params.n             = 2;
  mtst_send(SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE_TRACKS, mtst_enc_subtracks, &m);
}

/* 12-19, d22 3.6.2: SUBSCRIBE_TRACKS parameters are "explicitly
 * communicated in the PUBLISH"; of the ones d22 9.18 admits there, 9.8
 * lets FORWARD and GROUP_ORDER into a PUBLISH (AUTHORIZATION_TOKEN "MUST
 * NOT be copied", 9.20.2; the Range Filters and INCLUDE_PROPERTIES are
 * not PUBLISH parameters). So a FORWARD 1 that d19 10.19.1 lets the hub
 * omit is spelled out: Type 0x1D, Length, Request ID, Namespace ("chat"
 * "room1"), Name "alice", Track Alias, 2 Parameters: FORWARD (0x10) 1,
 * GROUP_ORDER (delta 0x12) 2, no Track Properties. */
static void test_moqtrun_misc_d22_publish_params(void) {
  static const u8 name[] = {0x02, 0x04, 'c', 'h',  'a', 't', 0x05, 'r', 'o',
                            'o',  'm',  '1', 0x05, 'a', 'l', 'i',  'c', 'e'};
  u8              want[64];
  usz             n          = 3;
  const wired_moqtrun_req* q = 0;
  g_moqtrun_test_ver         = MOQVER_D22;
  mtmi_subtracks_fwd1_go2();
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (mtst_hub.reqs[i].in_use && mtst_hub.reqs[i].pub_origin_rid)
      q = &mtst_hub.reqs[i];
  CHECK(q != 0);
  if (!q) return;
  CHECK(q->request_id < 64 && q->pub_alias < 64);
  want[n++] = (u8)q->request_id;
  bytes_memcpy(want + n, name, sizeof name);
  n += sizeof name;
  want[n++]                  = (u8)q->pub_alias;
  want[n++]                  = 2;
  want[n++]                  = 0x10;
  want[n++]                  = 0x01;
  want[n++]                  = 0x12;
  want[n++]                  = 0x02;
  want[0]                    = MOQCTL_T_PUBLISH;
  want[1]                    = 0;
  want[2]                    = (u8)(n - 3);
  const moqtrun_test_call* c = moqtrun_test_last_kind(1);
  CHECK(c != 0 && c->s == SESS_B && c->payload_len == n);
  CHECK(c && !ct_diffn(c->payload, want, n));
  g_moqtrun_test_ver = MOQVER_D19;
}

void test_moqtrun_misc(void) {
  moqtrun_test_allver(mtall_misc);
  test_moqtrun_misc_stray_update();
  test_moqtrun_misc_d22_publish_params();
}
