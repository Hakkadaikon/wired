/* Hub TRACK_STATUS (draft-ietf-moq-transport-19 10.14). Shares the recording io
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

void test_moqtrun_upd(void) {
  test_moqtrun_tstat_ok_largest();
  test_moqtrun_tstat_ok_empty();
  test_moqtrun_tstat_unknown_and_blob();
  test_moqtrun_tstat_authorized();
}
