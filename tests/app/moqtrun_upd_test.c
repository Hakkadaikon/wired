/* Hub TRACK_STATUS (draft-ietf-moq-transport-19 10.14) and REQUEST_UPDATE
 * on a subscription (10.9). Shares the recording io
 * stubs (moqtrun_test.c) and the subscription / request-stream fixtures
 * (moqtrun_sub_test.c) of the same unity TU. */

static int mtup_enc_tstat(wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_encode(buf, off, m);
}

/* TRACK_STATUS for f on request stream sid. */
static void mtup_tstat(wired_wt_session* s, u64 sid, const moqctl_ftn* f) {
  static moqctl_subscribe m;
  m.request_id = mtst_rid += 2;
  m.name       = *f;
  m.params.n   = 0;
  mtst_send(s, sid, MOQTSTAT_T_TRACK_STATUS, mtup_enc_tstat, &m);
}

static int mtup_enc_update(wired_mspan buf, usz* off, const void* m) {
  return moqtstat_update_encode(buf, off, m);
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
  moqctl_params q = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 9);
  moqctl_params r = mtst_params_filter(MOQCTL_FILTER_ABS_RANGE);
  moqctl_ftn    f = mtup_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &q);
  wired_moqtrun_sub* s          = mtst_sub(SESS_A, SESS_B);
  r.items[0].lf.start.group     = 5;
  r.items[0].lf.end_group_delta = 2;
  mtup_update(SESS_B, MTRQ_S1, &r);
  CHECK(s && s->start.group == 5 && s->has_end_group && s->end_group == 7);
  CHECK(s && s->has_priority && s->priority == 9);
  CHECK(mtup_reply(MTRQ_S1, &(wired_span){0, 0}) == MOQCTL_T_REQUEST_OK);
}

/* An update outlives the publisher: a rejoin re-attaches the updated
 * state (only the subscriber changes it, 5.1). */
static void test_moqtrun_upd_survives_rejoin(void) {
  moqctl_params p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_ftn    f  = mtup_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  mtup_update(SESS_B, MTRQ_S1, &p0);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  mtst_publish(SESS_A, mtst_join(SESS_A), &f, 1);
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

void test_moqtrun_upd(void) {
  test_moqtrun_tstat_ok_largest();
  test_moqtrun_tstat_ok_empty();
  test_moqtrun_tstat_unknown_and_blob();
  test_moqtrun_tstat_authorized();
  test_moqtrun_upd_forward_toggles();
  test_moqtrun_upd_params_replace();
  test_moqtrun_upd_survives_rejoin();
  test_moqtrun_upd_blob_forward();
  test_moqtrun_upd_bad_and_control();
}
