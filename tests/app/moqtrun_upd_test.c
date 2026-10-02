/* Hub TRACK_STATUS (draft-ietf-moq-transport-19 10.14), REQUEST_UPDATE on a
 * subscription (10.9), Location Filter delivery (5.1.4) and
 * OBJECT_DELIVERY_TIMEOUT (8, 10.2.4). Shares the recording io stubs
 * (moqtrun_test.c) and the subscription / request-stream fixtures
 * (moqtrun_sub_test.c) of the same unity TU. */

static int mtup_enc_tstat(wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_encode(buf, off, m);
}

static int mtup_enc_update(wired_mspan buf, usz* off, const void* m) {
  return moqtstat_update_encode(buf, off, m);
}

/* TRACK_STATUS for f on request stream sid. */
static void mtup_tstat(wired_wt_session* s, u64 sid, const moqctl_ftn* f) {
  static moqctl_subscribe m;
  m.request_id = mtst_rid += 2;
  m.name       = *f;
  m.params.n   = 0;
  mtst_send(s, sid, MOQTSTAT_T_TRACK_STATUS, mtup_enc_tstat, &m);
}

/* REQUEST_UPDATE carrying params on request stream sid; its Request ID is
 * a fresh one (draft 10.1: every REQUEST_UPDATE consumes one). */
static void mtup_update(
    wired_wt_session* s, u64 sid, const moqctl_params* params) {
  static moqtstat_update m;
  m.request_id = mtst_rid += 2;
  m.params     = *params;
  mtst_send(s, sid, MOQTSTAT_T_REQUEST_UPDATE, mtup_enc_update, &m);
}

/* Type of the last reply on request stream sid (first round via
 * stream_reply_open, later rounds via stream_send); *body its body. */
static u64 mtup_reply(u64 sid, wired_span* body) {
  for (usz i = g_n_calls; i > 0; i--) {
    const moqtrun_test_call* c   = &g_calls[i - 1];
    usz                      off = 0;
    u64                      type;
    if ((c->kind != 12 && c->kind != 3) || c->stream_id != sid) continue;
    if (moqctl_peek_type(
            wired_span_of(c->payload, c->payload_len), &off, &type, body) !=
        MOQCTL_OK)
      return 0;
    return type;
  }
  return 0;
}

/* The LARGEST_OBJECT of the last REQUEST_OK on sid; 0 if none. */
static const moqctl_param* mtup_ok_largest(u64 sid) {
  static moqctl_request_ok ok;
  wired_span               body;
  usz                      off = 0;
  if (mtup_reply(sid, &body) != MOQCTL_T_REQUEST_OK) return 0;
  if (moqctl_request_ok_take(body, &off, &ok) != MOQCTL_OK) return 0;
  return moqctl_params_find(&ok.params, MOQCTL_PARAM_LARGEST_OBJECT);
}

static u64 mtup_err_code(u64 sid) {
  moqctl_request_error e;
  wired_span           body;
  usz                  off = 0;
  if (mtup_reply(sid, &body) != MOQCTL_T_REQUEST_ERROR) return ~(u64)0;
  if (moqctl_request_error_take(body, &off, &e) != MOQCTL_OK) return ~(u64)0;
  return e.error_code;
}

/* A publishes f (alias 1) and sends Group 3 with two Objects (one-shot);
 * B joined. */
static moqctl_ftn mtup_setup(void) {
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_ftn f = mtrq_setup();
  usz        n = mtst_stream(3, 2, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 1);
  return f;
}

static moqctl_params mtup_vi(u64 type, u64 v) {
  moqctl_params p = {0};
  p.items[0].type = type;
  p.items[0].enc  = MOQCTL_PENC_VARINT;
  p.items[0].vi   = v;
  p.n             = 1;
  return p;
}

/* ===================== TRACK_STATUS (10.14) ===================== */

/* Answered like a SUBSCRIBE would be -- REQUEST_OK with the Largest
 * Location -- but no subscription is created, nothing is sent later, and
 * the stream is FINed. */
static void test_moqtrun_tstat_ok_largest(void) {
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_ftn f = mtup_setup();
  mtup_tstat(SESS_B, MTRQ_S1, &f);
  const moqctl_param* l = mtup_ok_largest(MTRQ_S1);
  CHECK(l != 0);
  CHECK(l && l->loc.group == 3 && l->loc.object == 1);
  CHECK(mtrq_fin_on(MTRQ_S1) == 1);
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
  moqtrun_test_reset();
  usz n = mtst_stream(4, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2005, wired_span_of(buf, n), 1);
  CHECK(moqtrun_test_count_kind(4) == 0);
}

/* Nothing published yet: REQUEST_OK without LARGEST_OBJECT. */
static void test_moqtrun_tstat_ok_empty(void) {
  moqctl_ftn f = mtrq_setup();
  mtup_tstat(SESS_B, MTRQ_S1, &f);
  CHECK(mtup_reply(MTRQ_S1, &(wired_span){0, 0}) == MOQCTL_T_REQUEST_OK);
  CHECK(mtup_ok_largest(MTRQ_S1) == 0);
}

/* An unknown track is DOES_NOT_EXIST; the hub's own blob track answers
 * without sending the blob. */
static void test_moqtrun_tstat_unknown_and_blob(void) {
  moqctl_ftn g = mtst_ftn("chat", "room1", "nobody");
  moqctl_ftn m = mtst_ftn("chat", "room1", "movie");
  mtrq_setup();
  mtup_tstat(SESS_B, MTRQ_S1, &g);
  CHECK(mtup_err_code(MTRQ_S1) == MOQCTL_ERR_DOES_NOT_EXIST);
  CHECK(mtrq_fin_on(MTRQ_S1) == 1);
  CHECK(moqtrun_test_publish_small_blob(&mtst_hub, 10) != 0);
  moqtrun_test_reset();
  mtup_tstat(SESS_B, MTRQ_S2, &m);
  CHECK(mtup_ok_largest(MTRQ_S2) != 0);
  CHECK(moqtrun_test_count_kind(4) == 0);
}

static int mtup_deny(void* ctx, const moqctl_ftn* n, const moqctl_token* t) {
  (void)ctx;
  (void)n;
  (void)t;
  return 0;
}

/* The SUBSCRIBE authorizer judges TRACK_STATUS too (13.3). */
static void test_moqtrun_tstat_authorized(void) {
  moqctl_ftn f                 = mtup_setup();
  mtst_hub.authorize_subscribe = mtup_deny;
  mtup_tstat(SESS_B, MTRQ_S1, &f);
  CHECK(mtup_err_code(MTRQ_S1) == MOQCTL_ERR_UNAUTHORIZED);
}

/* ===================== REQUEST_UPDATE (10.9) ===================== */

/* FORWARD 0 -> 1 starts delivery; REQUEST_OK carries the Largest
 * Location, which becomes the Joining Location (5.1). 1 -> 0 stops it. */
static void test_moqtrun_upd_forward_toggles(void) {
  moqctl_params p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_params p1 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  moqctl_ftn    f  = mtup_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &p0);
  CHECK(moqtrun_test_relay_alice_chat(&mtst_hub) == 0);
  mtup_update(SESS_B, MTRQ_S1, &p1);
  const moqctl_param* l = mtup_ok_largest(MTRQ_S1);
  CHECK(l && l->loc.group == 3);
  wired_moqtrun_sub* s = mtst_sub(SESS_A, SESS_B);
  CHECK(s && s->forward_off == 0 && s->has_jl && s->jl.group == 3);
  CHECK(moqtrun_test_relay_alice_chat(&mtst_hub) == 1);
  mtup_update(SESS_B, MTRQ_S1, &p0);
  CHECK(moqtrun_test_relay_alice_chat(&mtst_hub) == 0);
  CHECK(mtrq_fin_on(MTRQ_S1) == 0); /* still Established */
}

/* Present parameters replace, absent ones stay (10.9). */
static void test_moqtrun_upd_params_replace(void) {
  moqctl_params p = mtup_vi(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, 250);
  moqctl_params q = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 9);
  moqctl_params r = mtst_params_filter(MOQCTL_FILTER_ABS_RANGE);
  moqctl_ftn    f = mtup_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &q);
  mtup_update(SESS_B, MTRQ_S1, &p);
  wired_moqtrun_sub* s = mtst_sub(SESS_A, SESS_B);
  CHECK(s && s->has_delivery_timeout && s->delivery_timeout == 250);
  CHECK(s && s->has_priority && s->priority == 9);
  r.items[0].lf.start.group     = 5;
  r.items[0].lf.end_group_delta = 2;
  mtup_update(SESS_B, MTRQ_S1, &r);
  CHECK(s && s->start.group == 5 && s->has_end_group && s->end_group == 7);
  CHECK(s && s->delivery_timeout == 250);
  CHECK(mtup_reply(MTRQ_S1, &(wired_span){0, 0}) == MOQCTL_T_REQUEST_OK);
}

/* An update outlives a withdrawn PUBLISH: the republish re-attaches the
 * updated state (only the subscriber changes it, 5.1). The publisher's
 * session ending ends the subscription instead (PUBLISH_DONE). */
static void test_moqtrun_upd_survives_rejoin(void) {
  moqctl_params p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_ftn    f  = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, MTRQ_S2, &f, 1);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  mtup_update(SESS_B, MTRQ_S1, &p0);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S2, 0, 0);
  mtst_publish(SESS_A, MTRQ_S2 + 4, &f, 1);
  wired_moqtrun_sub* s = mtst_sub(SESS_A, SESS_B);
  CHECK(s && s->forward_off == 1);
  CHECK(moqtrun_test_relay_alice_chat(&mtst_hub) == 0);
}

/* FORWARD 0 -> 1 on the hub's blob sends it, once: a later 1 -> 0 -> 1
 * does not send it again. */
static void test_moqtrun_upd_blob_forward(void) {
  moqctl_params p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_params p1 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  moqctl_ftn    m  = mtst_ftn("chat", "room1", "movie");
  mtrq_setup();
  CHECK(moqtrun_test_publish_small_blob(&mtst_hub, 10) != 0);
  moqtrun_test_reset();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &m, 2, &p0);
  CHECK(moqtrun_test_count_kind(4) == 0);
  mtup_update(SESS_B, MTRQ_S1, &p1);
  CHECK(moqtrun_test_count_kind(4) == 1);
  mtup_update(SESS_B, MTRQ_S1, &p0);
  mtup_update(SESS_B, MTRQ_S1, &p1);
  CHECK(moqtrun_test_count_kind(4) == 1);
}

/* A parameter outside the update's scope (GROUP_ORDER, 10.2.8) is a
 * malformed message: PROTOCOL_VIOLATION. On the control stream there is
 * no request to update: NOT_SUPPORTED. */
/* draft 10.14: TRACK_STATUS is the only message of a new request stream;
 * on the control stream it is NOT_SUPPORTED. */
static void test_moqtrun_tstat_control_stream(void) {
  moqctl_ftn f  = mtup_setup();
  u64        cb = moqtrun_find_by_wt(&mtst_hub, SESS_B)->control_stream_id;
  mtup_tstat(SESS_B, cb, &f);
  CHECK(mtup_err_code(cb) == MOQCTL_ERR_NOT_SUPPORTED);
}

/* An update is all or nothing: when FORWARD 0 -> 1 cannot send the blob,
 * the priority it carried is not kept either -- and the failure ends the
 * subscription (10.9.1, PUBLISH_DONE UPDATE_FAILED). */
static void test_moqtrun_upd_failed_changes_nothing(void) {
  moqctl_params p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_params p1 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  moqctl_ftn    m  = mtst_ftn("chat", "room1", "movie");
  mtrq_setup();
  CHECK(moqtrun_test_publish_small_blob(&mtst_hub, 10) != 0);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &m, 2, &p0);
  p1.items[1].type = MOQCTL_PARAM_SUBSCRIBER_PRIORITY;
  p1.items[1].enc  = MOQCTL_PENC_UINT8;
  p1.items[1].u8v  = 9;
  p1.n             = 2;
  wired_moqtrun_sub* s =
      moqtrun_track_sub_of_peer(&mtst_hub.blob_track, mtst_idx(SESS_B));
  g_send_uni_fail_n = 1;
  mtup_update(SESS_B, MTRQ_S1, &p1);
  CHECK(mtup_err_code(MTRQ_S1) == MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(s && s->forward_off == 1 && s->has_priority == 0);
  CHECK(mtrq_fin_on(MTRQ_S1) == 1);
}

/* Reliable relay: FORWARD 1 -> 0 by update stops the open stream -- no
 * Object appended after the update reaches B (10.9.1); its stream is
 * reset CANCELLED and its cursor stops pinning the ring. */
static void test_moqtrun_upd_forward_off_reliable(void) {
  u8            buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_params p0              = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_ftn    f               = mtrq_setup();
  mtst_hub.reliable_alias_limit = 100;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  wired_moqt_tick(&mtst_hub, 0);
  usz n = mtst_stream(1, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 0);
  u64 sid = moqtrun_test_last_kind(5)->stream_id;
  mtup_update(SESS_B, MTRQ_S1, &p0);
  moqtrun_test_reset();
  n = mtst_stream(1, 1, 0, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 0);
  wired_moqt_tick(&mtst_hub, 5);
  for (usz i = 0; i < g_n_calls; i++)
    CHECK(!(g_calls[i].kind == 3 && g_calls[i].stream_id == sid));
  CHECK(mtrq_reset_code(sid) == 0x1);
}

static void test_moqtrun_upd_bad_and_control(void) {
  moqctl_params g  = mtst_params_u8(MOQCTL_PARAM_GROUP_ORDER, 1);
  moqctl_ftn    f  = mtup_setup();
  u64           cb = moqtrun_find_by_wt(&mtst_hub, SESS_B)->control_stream_id;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  mtup_update(SESS_B, cb, &g);
  CHECK(mtrq_type_on(3, cb) == MOQCTL_T_REQUEST_ERROR);
  mtup_update(SESS_B, MTRQ_S1, &g);
  CHECK(mtrq_closes() == 1);
}

/* ===================== Location Filter delivery (5.1.4) ============== */

/* AbsoluteRange start Group 2, end Group 3: Groups 1 and 4 never reach
 * the subscriber, nor does a datagram of Group 0. */
static void test_moqtrun_filter_groups_delivered(void) {
  u8            buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_params r               = mtst_params_filter(MOQCTL_FILTER_ABS_RANGE);
  moqctl_ftn    f               = mtrq_setup();
  r.items[0].lf.start.group     = 2;
  r.items[0].lf.end_group_delta = 1;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &r);
  moqtrun_test_reset();
  for (u64 g = 1; g <= 4; g++) {
    usz n = mtst_stream(g, 1, 1, buf);
    wired_moqt_on_stream_data(
        &mtst_hub, SESS_A, 2002 + 4 * g, wired_span_of(buf, n), g != 2);
  }
  CHECK(moqtrun_test_count_kind(4) == 1); /* Group 3, one-shot */
  CHECK(moqtrun_test_count_kind(5) == 1); /* Group 2, keep-open */
  wired_moqt_on_datagram(
      &mtst_hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
  CHECK(moqtrun_test_count_kind(9) == 0);
}

/* ===================== delivery timeout (8) ===================== */

/* A non-zero OBJECT_DELIVERY_TIMEOUT is accepted (SUBSCRIBE_OK). */
static void test_moqtrun_timeout_accepted(void) {
  moqctl_params p = mtup_vi(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, 100);
  moqctl_ftn    f = mtrq_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &p);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
}

/* B subscribed with OBJECT_DELIVERY_TIMEOUT t (absent when t is ~0) to a
 * reliable track; the stream's first round reaches B at clock 0, and the
 * next Object's round is refused. Returns B's relay stream id. */
static u64 mtup_ring_lagging(u64 t) {
  u8            buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_params p = mtup_vi(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, t);
  moqctl_ftn    f = mtrq_setup();
  mtst_hub.reliable_alias_limit = 100;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, t == ~(u64)0 ? 0 : &p);
  wired_moqt_tick(&mtst_hub, 0);
  usz n = mtst_stream(1, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 0);
  u64 sid                   = moqtrun_test_last_kind(5)->stream_id;
  g_stream_send_reject_sess = SESS_B;
  n                         = mtst_stream(1, 1, 0, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 0);
  return sid;
}

/* Reliable relay: an Object still unsent past the timeout resets B's
 * stream with DELIVERY_TIMEOUT (0x2); before it, the retry delivers. */
static void test_moqtrun_timeout_ring(void) {
  u64 sid = mtup_ring_lagging(100);
  wired_moqt_tick(&mtst_hub, 50);
  CHECK(mtrq_reset_code(sid) == -1);
  wired_moqt_tick(&mtst_hub, 150);
  CHECK(mtrq_reset_code(sid) == 0x2);
  CHECK(mtst_hub.stat_timeout_reset == 1);
  sid                       = mtup_ring_lagging(100);
  g_stream_send_reject_sess = 0;
  wired_moqt_tick(&mtst_hub, 50);
  moqtrun_test_reset();
  wired_moqt_tick(&mtst_hub, 150);
  CHECK(mtrq_reset_code(sid) == -1);
  CHECK(moqtrun_test_count_kind(3) == 0); /* delivered at 50 */
}

/* Timeout 0 (or none) never expires an Object. */
static void test_moqtrun_timeout_zero(void) {
  u64 sid = mtup_ring_lagging(0);
  wired_moqt_tick(&mtst_hub, 5000);
  CHECK(mtrq_reset_code(sid) == -1);
  sid = mtup_ring_lagging(~(u64)0);
  wired_moqt_tick(&mtst_hub, 5000);
  CHECK(mtrq_reset_code(sid) == -1);
}

/* A timeout set by REQUEST_UPDATE applies from then on. */
static void test_moqtrun_timeout_by_update(void) {
  moqctl_params p   = mtup_vi(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, 100);
  u64           sid = mtup_ring_lagging(~(u64)0);
  mtup_update(SESS_B, MTRQ_S1, &p);
  wired_moqt_tick(&mtst_hub, 150);
  CHECK(mtrq_reset_code(sid) == 0x2);
}

/* Lossy relay: an Object torn across deliveries is passed on when its
 * rest arrives -- unless its first byte came in longer than the timeout
 * ago: then B's stream is reset (0x2) and no later Object of that
 * Subgroup reopens it. */
static void test_moqtrun_timeout_torn_object(void) {
  u8            buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_params p = mtup_vi(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, 100);
  moqctl_ftn    f = mtrq_setup();
  for (int late = 0; late < 2; late++) {
    mtrq_setup();
    mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &p);
    wired_moqt_tick(&mtst_hub, 0);
    usz n = mtst_stream(1, 2, 1, buf);
    wired_moqt_on_stream_data(
        &mtst_hub, SESS_A, 2001, wired_span_of(buf, n - 1), 0);
    u64 sid = moqtrun_test_last_kind(5)->stream_id;
    wired_moqt_tick(&mtst_hub, late ? 150 : 50);
    moqtrun_test_reset();
    wired_moqt_on_stream_data(
        &mtst_hub, SESS_A, 2001, wired_span_of(buf + n - 1, 1), 0);
    CHECK(mtrq_reset_code(sid) == (late ? 0x2 : -1));
    CHECK(mtst_hub.stat_timeout_reset == (u64)late);
    CHECK(moqtrun_test_count_kind(3) == (usz)!late);
    n = mtst_stream(1, 1, 0, buf);
    wired_moqt_on_stream_data(
        &mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 0);
    CHECK(moqtrun_test_count_kind(5) == 0); /* never reopened */
  }
}

/* The hub's live track: a Group older than the timeout at send time is
 * not opened; the next one, still fresh, is. */
static void test_moqtrun_timeout_live(void) {
  moqctl_params p = mtup_vi(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, 100);
  moqctl_ftn    m = mtst_ftn("chat", "room1", "movie");
  mtrq_setup();
  moqtrun_test_publish_live(&mtst_hub); /* Group 0 at 1000, 2000 ms each */
  wired_moqt_tick(&mtst_hub, 1500);
  moqtrun_test_reset();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &m, 2, &p);
  wired_moqt_tick(&mtst_hub, 1600);
  CHECK(moqtrun_test_count_kind(8) == 0);
  wired_moqt_tick(&mtst_hub, 3050);
  CHECK(moqtrun_test_count_kind(8) == 1);
}

/* A datagram is relayed the moment it arrives: never past its timeout. */
static void test_moqtrun_timeout_datagram(void) {
  moqctl_params p = mtup_vi(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, 1);
  moqctl_ftn    f = mtrq_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &p);
  wired_moqt_tick(&mtst_hub, 5000);
  wired_moqt_on_datagram(
      &mtst_hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
  CHECK(moqtrun_test_count_kind(9) == 1);
}

void test_moqtrun_upd(void) {
  test_moqtrun_tstat_ok_largest();
  test_moqtrun_tstat_ok_empty();
  test_moqtrun_tstat_unknown_and_blob();
  test_moqtrun_tstat_authorized();
  test_moqtrun_tstat_control_stream();
  test_moqtrun_upd_failed_changes_nothing();
  test_moqtrun_upd_forward_off_reliable();
  test_moqtrun_upd_forward_toggles();
  test_moqtrun_upd_params_replace();
  test_moqtrun_upd_survives_rejoin();
  test_moqtrun_upd_blob_forward();
  test_moqtrun_upd_bad_and_control();
  test_moqtrun_filter_groups_delivered();
  test_moqtrun_timeout_accepted();
  test_moqtrun_timeout_ring();
  test_moqtrun_timeout_zero();
  test_moqtrun_timeout_by_update();
  test_moqtrun_timeout_torn_object();
  test_moqtrun_timeout_live();
  test_moqtrun_timeout_datagram();
}
