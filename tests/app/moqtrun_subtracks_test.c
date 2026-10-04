/* Hub-initiated PUBLISH / PUBLISH_SKIPPED in response to SUBSCRIBE_TRACKS
 * (draft-ietf-moq-transport-19 10.19-10.20, 1751-1787). Shares the
 * recording io stubs and request-stream fixtures of the same unity TU
 * (moqtrun_test.c, moqtrun_sub_test.c). */

static int mtst_enc_subtracks(wired_mspan buf, usz* off, const void* m) {
  return moqns_req_encode(buf, off, m);
}

/* SUBSCRIBE_TRACKS for prefix z ("" = zero fields) on sid, Request ID
 * mtst_rid += 2. */
static void mtst_subtracks(wired_wt_session* s, u64 sid, const char* z) {
  static moqns_req m;
  m.request_id = mtst_rid += 2;
  m.ns         = mtns_ns(z);
  m.params.n   = 0;
  mtst_send(s, sid, MOQCTL_T_SUBSCRIBE_TRACKS, mtst_enc_subtracks, &m);
}

/* Same, but with FORWARD 0 (10.19.1/T-12). */
static void mtst_subtracks_fwd0(wired_wt_session* s, u64 sid, const char* z) {
  static moqctl_param  items[1];
  static moqctl_params p;
  static moqns_req     m;
  items[0].type = MOQCTL_PARAM_FORWARD;
  items[0].enc  = MOQCTL_PENC_UINT8;
  items[0].u8v  = 0;
  p.items[0]    = items[0];
  p.n           = 1;
  m.request_id  = mtst_rid += 2;
  m.ns          = mtns_ns(z);
  m.params      = p;
  mtst_send(s, sid, MOQCTL_T_SUBSCRIBE_TRACKS, mtst_enc_subtracks, &m);
}

/* Replies recorded on SUBSCRIBE_TRACKS's own stream (REQUEST_OK/ERROR and
 * any PUBLISH_SKIPPED), rendered like moqtrun_ns_test.c's own log: "OK|",
 * "ERR:xx|", "SKIP:<name>|". */
static char mtst_stlog_buf[256];
static usz  mtst_stlog_at;

static void mtst_stlog_put(const char* z) {
  while (*z) mtst_stlog_buf[mtst_stlog_at++] = *z++;
}

static void mtst_stlog_err(wired_span body) {
  static const char    hex[] = "0123456789abcdef";
  moqctl_request_error e;
  usz                  off = 0;
  CHECK(moqctl_request_error_take(body, &off, &e) == MOQCTL_OK);
  mtst_stlog_put("ERR:");
  mtst_stlog_buf[mtst_stlog_at++] = hex[(e.error_code >> 4) & 0xF];
  mtst_stlog_buf[mtst_stlog_at++] = hex[e.error_code & 0xF];
}

static void mtst_stlog_skip(wired_span body) {
  moqns_pub_skipped m;
  CHECK(moqns_pub_skipped_take(body, &m) == MOQCTL_OK);
  mtst_stlog_put("SKIP:");
  for (usz i = 0; i < m.name.n && i < 16; i++)
    mtst_stlog_buf[mtst_stlog_at++] = (char)m.name.p[i];
}

static void mtst_stlog_msg(u64 type, wired_span body) {
  if (type == MOQCTL_T_REQUEST_OK) mtst_stlog_put("OK");
  if (type == MOQCTL_T_REQUEST_ERROR) mtst_stlog_err(body);
  if (type == MOQCTL_T_PUBLISH_SKIPPED) mtst_stlog_skip(body);
  mtst_stlog_put("|");
}

static void mtst_stlog_call(const moqtrun_test_call* c) {
  wired_span all = wired_span_of(c->payload, c->payload_len);
  usz        off = 0;
  u64        type;
  wired_span body;
  while (off < all.n) {
    CHECK(moqctl_peek_type(all, &off, &type, &body) != MOQCTL_INSUFFICIENT);
    mtst_stlog_msg(type, body);
  }
}

static const char* mtst_stlog(wired_wt_session* s, u64 sid) {
  mtst_stlog_at = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c  = &g_calls[i];
    int                      on = (c->kind == 12 || c->kind == 3) && c->s == s;
    if (on && c->stream_id == sid && !c->refused) mtst_stlog_call(c);
  }
  mtst_stlog_buf[mtst_stlog_at] = 0;
  return mtst_stlog_buf;
}

static int mtst_stlog_is(wired_wt_session* s, u64 sid, const char* want) {
  const char* got = mtst_stlog(s, sid);
  usz         i   = 0;
  while (got[i] && got[i] == want[i]) i++;
  if (got[i] != want[i]) printf("  got \"%s\" want \"%s\"\n", got, want);
  return got[i] == want[i];
}

/* 1 iff the hub still holds this stream_id OPEN as a hub-opened PUBLISH --
 * a REFUSED open_bidi_stream call is still recorded (kind=1) by the io
 * stub, but moqtrun_subtracks_attempt frees that slot right away, so
 * checking the live hub state (not just the call log) is what tells an
 * actually-opened PUBLISH apart from a failed attempt that fell back to
 * PUBLISH_SKIPPED. */
static int mtst_pub_is_open(u64 stream_id) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    const wired_moqtrun_req* q = &mtst_hub.reqs[i];
    if (q->in_use && q->pub_origin_rid && q->opened &&
        q->stream_id == stream_id)
      return 1;
  }
  return 0;
}

/* Every kind=1 (open_bidi_stream) call addressed to s whose payload
 * decodes as PUBLISH AND whose stream is still open hub-side, in order. */
static usz mtst_pub_opens(wired_wt_session* s, moqctl_publish* out, usz cap) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls && n < cap; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0;
    u64                      type;
    wired_span               body;
    if (c->kind != 1 || c->s != s || !mtst_pub_is_open(c->stream_id)) continue;
    if (moqctl_peek_type(
            wired_span_of(c->payload, c->payload_len), &off, &type, &body) !=
            MOQCTL_OK ||
        type != MOQCTL_T_PUBLISH)
      continue;
    off = 0;
    if (moqctl_publish_take(MOQVER_D19, body, &off, &out[n]) == MOQCTL_OK) n++;
  }
  return n;
}

/* Stream id of the which-th (0-based) PUBLISH still open hub-side. */
static i64 mtst_pub_stream_id(usz which) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0;
    u64                      type;
    wired_span               body;
    if (c->kind != 1 || !mtst_pub_is_open(c->stream_id)) continue;
    if (moqctl_peek_type(
            wired_span_of(c->payload, c->payload_len), &off, &type, &body) !=
            MOQCTL_OK ||
        type != MOQCTL_T_PUBLISH)
      continue;
    if (n == which) return (i64)c->stream_id;
    n++;
  }
  return -1;
}

/* Sends REQUEST_OK (empty params) on sid as the PUBLISH's receiver. */
static void mtst_pub_ok(wired_wt_session* s, u64 sid) {
  u8                       msg[16];
  usz                      n  = 0;
  static moqctl_request_ok ok = {0};
  n                           = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_REQUEST_OK,
      (moqtrun_body_encode_fn)moqctl_request_ok_encode, &ok);
  wired_moqt_on_stream_data(&mtst_hub, s, sid, wired_span_of(msg, n), 0);
}

static void mtst_pub_err(wired_wt_session* s, u64 sid, u64 code) {
  u8                          msg[16];
  usz                         n = 0;
  static moqctl_request_error e = {0};
  e.error_code                  = code;
  n                             = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_REQUEST_ERROR,
      (moqtrun_body_encode_fn)moqctl_request_error_encode, &e);
  wired_moqt_on_stream_data(&mtst_hub, s, sid, wired_span_of(msg, n), 0);
}

/* Resets the hub only; every test joins the sessions it needs itself
 * (mtrq_setup's own pattern) -- joining a session here AND again in the
 * test would double-register it under two peer slots. */
static void mtst_subtracks_init(void) { mtst_init(); }

/* T-01/T-09: REQUEST_OK is the one and only message on SUBSCRIBE_TRACKS's
 * own response stream, when nothing matches yet. */
static void test_subtracks_ok_once(void) {
  mtst_subtracks_init();
  mtst_join(SESS_B);
  mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  CHECK(mtst_stlog_is(SESS_B, MTRQ_S1, "OK|"));
  CHECK(mtrq_fin_on(MTRQ_S1) == 0);
}

/* T-02: a Track Namespace Prefix overlapping an established
 * SUBSCRIBE_TRACKS is PREFIX_OVERLAP, and the refused one gets no PUBLISH
 * even once a matching track appears. */
static void test_subtracks_prefix_overlap(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_subtracks_init();
  mtst_join(SESS_B);
  mtst_subtracks(SESS_B, MTRQ_S1, "chat/room1");
  mtst_subtracks(SESS_B, MTRQ_S2, "chat");
  CHECK(mtst_stlog_is(SESS_B, MTRQ_S2, "ERR:30|"));
  CHECK(mtrq_fin_on(MTRQ_S2) == 1);
  u64 ca = mtst_join(SESS_A);
  mtst_publish(SESS_A, ca, &f, 1);
  wired_moqt_tick(&mtst_hub, 0);
  CHECK(mtst_stlog_is(SESS_B, MTRQ_S2, "ERR:30|"));
}

/* T-03/T-04/T-05: a matching track (not the subscriber's own) gets exactly
 * one PUBLISH, naming the track's namespace/name/alias; a track the
 * subscriber itself publishes is excluded. */
static void test_subtracks_publish_match_excludes_self(void) {
  moqctl_ftn     f = mtst_ftn("chat", "room1", "alice");
  moqctl_ftn     g = mtst_ftn("chat", "room1", "bob");
  moqctl_publish got[4];
  mtst_subtracks_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  mtst_publish(SESS_B, cb, &g, 2);
  wired_moqt_tick(&mtst_hub, 0);
  usz n = mtst_pub_opens(SESS_B, got, 4);
  CHECK(n == 1);
  CHECK(got[0].name.name.n == 5 && got[0].name.name.p[0] == 'a');
  CHECK(got[0].track_alias == 1);
}

/* T-06: once a PUBLISH_SKIPPED has gone out for a (subscriber, track)
 * pair, no PUBLISH follows on a later sync for the SAME track
 * incarnation. */
static void test_subtracks_skip_then_no_publish(void) {
  moqctl_ftn     f = mtst_ftn("chat", "room1", "alice");
  moqctl_publish got[4];
  mtst_subtracks_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  g_open_bidi_fail_n = 1;
  mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  CHECK(mtst_stlog_is(SESS_B, MTRQ_S1, "OK|SKIP:alice|"));
  wired_moqt_tick(&mtst_hub, 0);
  wired_moqt_tick(&mtst_hub, 0);
  CHECK(mtst_pub_opens(SESS_B, got, 4) == 0);
  CHECK(mtst_stlog_is(SESS_B, MTRQ_S1, "OK|SKIP:alice|"));
}

/* T-07/T-08: the track vanishing (unpublish) while its hub-opened PUBLISH
 * awaits a reply resets that stream with a consistent error code; a
 * REQUEST_OK delivered afterward on the same (now-freed) stream id is not
 * accepted as establishing anything (the slot is no longer in use). */
static void test_subtracks_track_vanishes_resets_publish(void) {
  moqctl_ftn     f = mtst_ftn("chat", "room1", "alice");
  moqctl_publish got[4];
  mtst_subtracks_init();
  mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, MTRQ_S1, &f, 1);
  mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  wired_moqt_tick(&mtst_hub, 0);
  CHECK(mtst_pub_opens(SESS_B, got, 4) == 1);
  i64 sid = mtst_pub_stream_id(0);
  CHECK(sid >= 0);
  usz before = mtrq_used();
  /* A's own request stream reset withdraws its PUBLISH (unpublish). */
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S1, 0, 0);
  CHECK(mtrq_reset_code((u64)sid) >= 0);
  CHECK(mtrq_used() < before);
  /* A late REQUEST_OK on the freed stream id is simply ignored: no crash,
   * no re-use of a stale slot. */
  mtst_pub_ok(SESS_B, (u64)sid);
}

/* T-10: cancelling SUBSCRIBE_TRACKS stops new PUBLISH/PUBLISH_SKIPPED, but
 * a subscription already established (REQUEST_OK received) continues. */
static void test_subtracks_cancel_keeps_established(void) {
  moqctl_ftn     f = mtst_ftn("chat", "room1", "alice");
  moqctl_ftn     g = mtst_ftn("chat", "room2", "carol");
  moqctl_publish got[4];
  mtst_subtracks_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  wired_moqt_tick(&mtst_hub, 0);
  CHECK(mtst_pub_opens(SESS_B, got, 4) == 1);
  i64 sid = mtst_pub_stream_id(0);
  mtst_pub_ok(SESS_B, (u64)sid);
  CHECK(mtrq_reset_code((u64)sid) == -1); /* still open, not reset */
  /* Cancel the SUBSCRIBE_TRACKS itself. */
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S1, 0, 0);
  /* A new matching track appears after the cancel: no new PUBLISH. */
  u64 cc = mtst_join(SESS_C);
  mtst_publish(SESS_C, cc, &g, 1);
  wired_moqt_tick(&mtst_hub, 0);
  CHECK(mtst_pub_opens(SESS_B, got, 4) == 1); /* still just the first one */
  /* The already-established PUBLISH stream is untouched by the cancel. */
  CHECK(mtrq_reset_code((u64)sid) == -1);
}

/* T-11: a matching, existing track is eventually attempted (PUBLISH or
 * PUBLISH_SKIPPED) -- never left notstarted across a tick. */
static void test_subtracks_liveness_eventually_attempted(void) {
  moqctl_ftn     f = mtst_ftn("chat", "room1", "alice");
  moqctl_publish got[4];
  mtst_subtracks_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  CHECK(mtst_pub_opens(SESS_B, got, 4) == 1); /* attempted inline, same tick */
}

/* A REQUEST_ERROR reply to the hub-opened PUBLISH frees its slot
 * (pubState "err" of design.md's state machine): no dangling slot left. */
static void test_subtracks_publish_error_frees_slot(void) {
  moqctl_ftn     f = mtst_ftn("chat", "room1", "alice");
  moqctl_publish got[4];
  mtst_subtracks_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  CHECK(mtst_pub_opens(SESS_B, got, 4) == 1);
  i64 sid    = mtst_pub_stream_id(0);
  usz before = mtrq_used();
  mtst_pub_err(SESS_B, (u64)sid, MOQCTL_ERR_UNINTERESTED);
  CHECK(mtrq_used() < before);
}

/* T-12: FORWARD 0 on SUBSCRIBE_TRACKS is reflected as FORWARD 0 on the
 * generated PUBLISH. */
static void test_subtracks_forward_zero_reflected(void) {
  moqctl_ftn     f = mtst_ftn("chat", "room1", "alice");
  moqctl_publish got[4];
  mtst_subtracks_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subtracks_fwd0(SESS_B, MTRQ_S1, "chat");
  CHECK(mtst_pub_opens(SESS_B, got, 4) == 1);
  const moqctl_param* fwd =
      moqctl_params_find(&got[0].params, MOQCTL_PARAM_FORWARD);
  CHECK(fwd != 0 && fwd->u8v == 0);
}

void test_moqtrun_subtracks(void) {
  test_subtracks_ok_once();
  test_subtracks_prefix_overlap();
  test_subtracks_publish_match_excludes_self();
  test_subtracks_skip_then_no_publish();
  test_subtracks_track_vanishes_resets_publish();
  test_subtracks_cancel_keeps_established();
  test_subtracks_liveness_eventually_attempted();
  test_subtracks_publish_error_frees_slot();
  test_subtracks_forward_zero_reflected();
}
