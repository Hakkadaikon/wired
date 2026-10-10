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

/* B's SUBSCRIBE_TRACKS "chat" carrying sp, after A published
 * chat/room1/alice (alias 1). */
static void mtmi_subtracks_p(const moqctl_params* sp) {
  static moqns_req m;
  moqctl_ftn       f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  moqtrun_test_reset();
  m.request_id = mtst_rid += 2;
  m.ns         = mtns_ns("chat");
  m.params     = *sp;
  mtst_send(SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE_TRACKS, mtst_enc_subtracks, &m);
}

/* The hub's PUBLISH stream to B after mtmi_subtracks_p, accepted with
 * REQUEST_OK; ~0 when none opened. */
static u64 mtmi_accepted(void) {
  moqctl_publish pub;
  i64            sid = mtst_pub_stream_id(0);
  CHECK(mtst_pub_opens(SESS_B, &pub, 1) == 1);
  if (sid < 0) return ~(u64)0;
  mtst_pub_ok(SESS_B, (u64)sid);
  return (u64)sid;
}

/* Datagrams relayed to B for A's MOQTRUN_TEST_DG_CHAT (Object 5). */
static usz mtmi_dg_to_b(void) {
  usz n = 0;
  moqtrun_test_reset();
  wired_moqt_on_datagram(
      &mtst_hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
  for (usz i = 0; i < g_n_calls; i++)
    n += g_calls[i].kind == 9 && g_calls[i].s == SESS_B;
  return n;
}

/* 12-26, d22 3.6.1 "Objects published in the resulting Subscriptions can
 * be filtered by any Range Filter" and 3.6.2 "These parameters are used by
 * the publisher as the initial Subscription parameters" (d19 10.19.1
 * "copied over as the default Subscription parameters"): an
 * OBJECTID_FILTER on SUBSCRIBE_TRACKS gates the resulting subscription
 * though the PUBLISH cannot carry it (d22 9.8). {0..4} drops Object 5,
 * {5..9} passes it. */
static void test_moqtrun_misc_subtracks_rngf_gates(void) {
  moqctl_params      lo = {0}, hi = {0};
  moqctl_rangefilter f0 = mtst_rngf1(0, 0, 4, 1);
  moqctl_rangefilter f5 = mtst_rngf1(0, 5, 9, 1);
  mtst_rngf_param(&lo, MOQCTL_PARAM_OBJECTID_FILTER, &f0);
  mtst_rngf_param(&hi, MOQCTL_PARAM_OBJECTID_FILTER, &f5);
  mtmi_subtracks_p(&lo);
  mtmi_accepted();
  CHECK(mtmi_dg_to_b() == 0);
  mtmi_subtracks_p(&hi);
  mtmi_accepted();
  CHECK(mtmi_dg_to_b() == 1);
}

/* d22 3.3.2 / 9.20.14: a TRACK_PROPERTY_FILTER on SUBSCRIBE_TRACKS lets
 * only tracks whose Track Property is in range be PUBLISHed: A's track
 * has property 0x0E = 5, so {0..9} matches it and {10..20} does not. */
static void test_moqtrun_misc_subtracks_track_prop_filter(void) {
  static const u8    props[] = {0x0E, 0x05};
  static moqns_req   m;
  moqctl_ftn         f   = mtst_ftn("chat", "room1", "alice");
  moqctl_rangefilter in  = mtst_rngf1(0, 0, 9, 1);
  moqctl_rangefilter out = mtst_rngf1(0, 10, 20, 1);
  moqctl_publish     pub;
  moqctl_params      pin = {0}, pout = {0};
  in.has_prop = out.has_prop = 1;
  in.prop_type = out.prop_type = 0x0E;
  mtst_rngf_param(&pin, MOQCTL_PARAM_TRACK_PROPERTY_FILTER, &in);
  mtst_rngf_param(&pout, MOQCTL_PARAM_TRACK_PROPERTY_FILTER, &out);
  for (int k = 0; k < 2; k++) {
    mtst_init();
    u64 ca = mtst_join(SESS_A);
    mtst_join(SESS_B);
    mtst_publish_props(SESS_A, ca, &f, 1, wired_span_of(props, sizeof props));
    m.request_id = mtst_rid += 2;
    m.ns         = mtns_ns("chat");
    m.params     = k ? pout : pin;
    mtst_send(
        SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE_TRACKS, mtst_enc_subtracks, &m);
    wired_moqt_tick(&mtst_hub, 0);
    CHECK(mtst_pub_opens(SESS_B, &pub, 1) == (usz)(k == 0));
  }
}

/* 12-26, d22 3.3.2 / d19 5.1.3: "If this limit is exceeded, an endpoint
 * MUST reject this with REQUEST_ERROR with error code INVALID_FILTER" --
 * SUBSCRIBE_TRACKS included; no PUBLISH follows. */
static void test_moqtrun_misc_subtracks_rngf_limit(void) {
  moqctl_params      over = {0};
  moqctl_rangefilter four = mtst_rngf1(0, 0, 4, 1);
  moqctl_rangefilter one  = mtst_rngf1(1, 9, 9, 1);
  moqctl_publish     pub;
  four.n = 4;
  for (usz i = 1; i < 4; i++) {
    four.r[i].start   = 10 * i;
    four.r[i].end     = 10 * i + 1;
    four.r[i].has_end = 1;
  }
  mtst_rngf_param(&over, MOQCTL_PARAM_SUBGROUP_FILTER, &one);
  mtst_rngf_param(&over, MOQCTL_PARAM_OBJECTID_FILTER, &four);
  mtmi_subtracks_p(&over);
  CHECK(mtrq_err_on(MTRQ_S1) == MOQCTL_ERR_INVALID_FILTER);
  CHECK(mtst_pub_opens(SESS_B, &pub, 1) == 0);
}

/* 12-27, d19 10.9.1 / d22 9.5.1: a failed update "MUST also terminate the
 * subscription by sending a PUBLISH_DONE with error code UPDATE_FAILED",
 * and "A publisher sends a PUBLISH_DONE message as the final message
 * before closing the subscription's bidi stream" (d19 10.11, d22 9.9; d18
 * 10.11 "A sender SHOULD send FIN on the subscription's bidi stream
 * immediately after sending PUBLISH_DONE") -- the hub FINs the PUBLISH
 * stream. 12-28: a
 * REQUEST_OK after that is a second response and closes the session
 * instead of reopening the subscription. */
static void test_moqtrun_misc_pub_update_failed_fins(void) {
  moqctl_params      bad = {0}, none = {0};
  moqctl_rangefilter f0 = mtst_rngf1(0, 0, 4, 1);
  mtst_rngf_param(&bad, MOQCTL_PARAM_OBJECTID_FILTER, &f0);
  mtst_rngf_param(&bad, MOQCTL_PARAM_OBJECTID_FILTER, &f0); /* dup id */
  mtmi_subtracks_p(&none);
  u64 sid = mtmi_accepted();
  mtup_update(SESS_B, sid, &bad);
  CHECK(mtup_err_code(sid) == MOQCTL_ERR_INVALID_FILTER);
  CHECK(mtrq_fin_on(sid) == 1);
  mtst_pub_ok(SESS_B, sid);
  CHECK(mtrq_closes() == 1);
  CHECK(mtmi_dg_to_b() == 0);
}

/* 12-28, d18/d19 5.1 / d22 3.1 (Subscriptions): "A subscriber
 * MUST send exactly one PUBLISH_OK ... or REQUEST_ERROR in response to a
 * PUBLISH. The peer SHOULD close the session with a protocol error if it
 * receives more than one." -- the same sentence in all three drafts, so
 * no version gate. */
static void test_moqtrun_misc_pub_second_ok_closes(void) {
  moqctl_publish pub;
  u64            sid = mtmi_setup(0, &pub);
  mtst_pub_ok(SESS_B, sid);
  CHECK(mtrq_closes() == 0);
  mtst_pub_ok(SESS_B, sid);
  CHECK(mtrq_closes() == 1);
}

/* 12-28: a REQUEST_ERROR after the REQUEST_OK is the same "more than
 * one". */
static void test_moqtrun_misc_pub_error_after_ok_closes(void) {
  moqctl_publish pub;
  u64            sid = mtmi_setup(0, &pub);
  mtst_pub_ok(SESS_B, sid);
  mtst_pub_err(SESS_B, sid, MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(mtrq_closes() == 1);
}

/* B's REQUEST_OK on the PUBLISH stream sid carrying params sp; 1 when
 * that body decodes under the session's draft (the codec's own per-draft
 * parameter scope, moqctl_request_ok_take). */
static int mtmi_pub_ok_p(u64 sid, const moqctl_params* sp) {
  u8                       msg[96];
  usz                      off = 0, boff = 0;
  u64                      type;
  wired_span               body;
  static moqctl_request_ok ok, back;
  ok.params = *sp;
  usz n     = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_REQUEST_OK,
      (moqtrun_body_encode_fn)moqctl_request_ok_encode, &ok);
  wired_moqt_on_stream_data(&mtst_hub, SESS_B, sid, wired_span_of(msg, n), 0);
  if (moqctl_peek_type(wired_span_of(msg, n), &off, &type, &body) != MOQCTL_OK)
    return 0;
  return moqctl_request_ok_take(g_moqtrun_test_ver, body, &boff, &back) ==
         MOQCTL_OK;
}

/* A refused PUBLISH_OK on sid: where the draft lets PUBLISH_OK carry
 * filters (d19 5.1.3), REQUEST_ERROR INVALID_FILTER on the PUBLISH stream,
 * which the hub then FINs; where it does not (d22 9.3: PUBLISH_OK admits
 * EXPIRES only, "Subscription parameters appear in REQUEST_UPDATE, not
 * PUBLISH_OK"), the body is malformed and the session closes
 * PROTOCOL_VIOLATION (12-13). Either way no subscription opens. */
static void mtmi_pub_ok_refused(u64 sid, int decodes) {
  CHECK(g_moqtrun_test_ver != MOQVER_D19 || decodes);
  if (decodes) {
    CHECK(mtrq_err_on(sid) == MOQCTL_ERR_INVALID_FILTER);
    CHECK(mtrq_fin_on(sid) == 1);
    CHECK(mtrq_closes() == 0);
  }
  if (!decodes) CHECK(mtrq_closes() == 1);
  CHECK(mtmi_dg_to_b() == 0);
}

/* 12-30, d19 5.1.3: filter parameters "MAY appear multiple times in a
 * ... PUBLISH_OK ... If the same combination of Parameter Type, SetID,
 * and Property Type ... repeat in any message, an endpoint MUST reject
 * this with REQUEST_ERROR with error code INVALID_FILTER". */
static void test_moqtrun_misc_pub_ok_bad_filter(void) {
  moqctl_params      bad = {0}, none = {0};
  moqctl_rangefilter f0 = mtst_rngf1(0, 0, 4, 1);
  mtst_rngf_param(&bad, MOQCTL_PARAM_OBJECTID_FILTER, &f0);
  mtst_rngf_param(&bad, MOQCTL_PARAM_OBJECTID_FILTER, &f0); /* dup id */
  mtmi_subtracks_p(&none);
  i64 sid = mtst_pub_stream_id(0);
  CHECK(sid >= 0);
  mtmi_pub_ok_refused((u64)sid, mtmi_pub_ok_p((u64)sid, &bad));
}

/* 12-30, d19 5.1.3 "Range Filters ... limits the total number of Ranges
 * allowed in all Range Filter parameters for a given subscription ... If
 * this limit is exceeded, an endpoint MUST reject this with REQUEST_ERROR
 * with error code INVALID_FILTER": SUBSCRIBE_TRACKS's one Range plus a
 * PUBLISH_OK's MAX_FILTER_RANGES more of another type is one too many. */
static void test_moqtrun_misc_pub_ok_filter_over(void) {
  moqctl_params      sp = {0}, over = {0};
  moqctl_rangefilter one = mtst_rngf1(1, 9, 9, 1);
  moqctl_rangefilter all = mtst_rngf1(0, 0, 1, 1);
  all.n                  = WIRED_MOQTRUN_MAX_FILTER_RANGES;
  for (usz i = 1; i < all.n; i++) {
    all.r[i].start   = 10 * i;
    all.r[i].end     = 10 * i + 1;
    all.r[i].has_end = 1;
  }
  mtst_rngf_param(&sp, MOQCTL_PARAM_SUBGROUP_FILTER, &one);
  mtst_rngf_param(&over, MOQCTL_PARAM_OBJECTID_FILTER, &all);
  mtmi_subtracks_p(&sp);
  i64 sid = mtst_pub_stream_id(0);
  CHECK(sid >= 0);
  mtmi_pub_ok_refused((u64)sid, mtmi_pub_ok_p((u64)sid, &over));
}

/* 12-30: within the limit the same PUBLISH_OK filter is applied (d19
 * 10.19.1 / 5.1.3), so the hub's check does not refuse a good one. */
static void test_moqtrun_misc_pub_ok_filter_ok(void) {
  moqctl_params      lo = {0}, none = {0};
  moqctl_rangefilter f0 = mtst_rngf1(0, 0, 4, 1);
  mtst_rngf_param(&lo, MOQCTL_PARAM_OBJECTID_FILTER, &f0);
  mtmi_subtracks_p(&none);
  i64 sid = mtst_pub_stream_id(0);
  CHECK(sid >= 0);
  if (!mtmi_pub_ok_p((u64)sid, &lo)) return; /* d22: not a PUBLISH_OK param */
  CHECK(mtrq_closes() == 0);
  CHECK(mtrq_err_on((u64)sid) == ~(u64)0);
  CHECK(mtmi_dg_to_b() == 0); /* Object 5 is outside {0..4} */
}

static void mtrf_misc(void) {
  test_moqtrun_misc_subtracks_rngf_gates();
  test_moqtrun_misc_subtracks_track_prop_filter();
  test_moqtrun_misc_subtracks_rngf_limit();
  test_moqtrun_misc_pub_update_failed_fins();
  test_moqtrun_misc_pub_ok_bad_filter();
  test_moqtrun_misc_pub_ok_filter_over();
  test_moqtrun_misc_pub_ok_filter_ok();
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

/* 12-29, d19 3.3.2 / d22 6.4.2.2: "An endpoint SHOULD send a FIN promptly
 * after a message when it has nothing further to send on that direction"
 * and, once the responder is done, "the requester SHOULD then send a FIN
 * on its direction" (d18 3.3.2: a rejection is "a REQUEST_ERROR and FIN
 * the stream") -- a REQUEST_ERROR to the hub's PUBLISH completes the
 * request, so the hub FINs its side, and the slot frees once the peer's
 * side has ended too. */
static void test_moqtrun_misc_pub_error_fins(void) {
  moqctl_publish pub;
  u64            sid = mtmi_setup(0, &pub);
  moqtrun_test_reset();
  mtst_pub_err(SESS_B, sid, MOQCTL_ERR_UNINTERESTED);
  CHECK(mtrq_fin_on(sid) == 1);
  CHECK(mtrq_closes() == 0);
  CHECK(mtst_pub_is_open(sid) == 1);
  wired_moqt_on_stream_data(&mtst_hub, SESS_B, sid, wired_span_of(0, 0), 1);
  CHECK(mtst_pub_is_open(sid) == 0);
}

static void mtall_misc(void) {
  test_moqtrun_misc_pub_error_fins();
  test_moqtrun_misc_pub_ok_relays();
  test_moqtrun_misc_pub_forward0_then_update();
  test_moqtrun_misc_pub_update_before_ok();
  test_moqtrun_misc_pub_second_ok_closes();
  test_moqtrun_misc_pub_error_after_ok_closes();
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
  moqtrun_test_vers(MOQVER_CAP_RANGE_FILTERS, 0, mtrf_misc);
}
