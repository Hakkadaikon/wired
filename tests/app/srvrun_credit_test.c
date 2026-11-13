/* @file
 * #200: wired_srvrun_opt.wt_on_stream_credit -- a server-initiated WT open
 * refused for lack of credit fires the callback once the refusal no longer
 * holds (draft-ietf-webtrans-http3-16 5.3/5.6.2 WT_MAX_STREAMS, RFC 9000
 * 4.6/19.11 MAX_STREAMS). Reuses srvrun_test.c's sr_wtsend_fixture.
 *
 * Test list:
 * - no refused open: polling fires nothing.
 * - WT_MAX_STREAMS(uni) refusal: nothing while still refused; fires once
 *   with the session after the limit rises; not again on the next poll;
 *   the retried open then succeeds.
 * - QUIC MAX_STREAMS(uni) refusal: same, raised via the peer's limit.
 * - a refused open with no callback registered is cleared silently.
 * - bidi WT_MAX_STREAMS refusal and WT_MAX_DATA refusal fire the same way.
 * - send-slot share refusal fires once a slot of the session is freed.
 * - a full send table (share ok, claim fails) arms too, and fires only once
 *   a slot is really free.
 * - an open refused again from inside the callback re-arms.
 * - a session closed while armed never fires. */

static int               g_crd_calls;
static wired_wt_session* g_crd_last;

static void crd_on_credit(void* ctx, wired_wt_session* s) {
  (void)ctx;
  g_crd_calls++;
  g_crd_last = s;
}

static srvrun_conn* crd_fixture(struct lp_fix* f, wired_obuf* ob) {
  srvrun_conn* c                         = sr_wtsend_fixture(f, ob);
  c->s.sdrv.peer_initial_max_streams_uni = 1000;
  g_srvrun_env.wt_on_stream_credit       = crd_on_credit;
  g_crd_calls                            = 0;
  g_crd_last                             = 0;
  return c;
}

static i64 crd_open(srvrun_conn* c) {
  return wired_server_wt_open_uni(
      &c->wt, wired_span_of(sr_wtsend_hello, sizeof sr_wtsend_hello));
}

static void test_srvrun_wt_credit_no_block_no_call(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c  = crd_fixture(&f, &ob);
  CHECK(crd_open(c) > 0);
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 0);
}

static void test_srvrun_wt_credit_after_wt_max_streams(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c  = crd_fixture(&f, &ob);
  CHECK(wired_wt_session_set_max_streams(&c->wt, 0, 1));
  CHECK(crd_open(c) > 0);
  CHECK(crd_open(c) == -1); /* WT_MAX_STREAMS(uni) = 1 reached */
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 0); /* still refused */
  CHECK(wired_wt_session_set_max_streams(&c->wt, 0, 2));
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 1 && g_crd_last == &c->wt);
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 1); /* once per refusal */
  CHECK(crd_open(c) > 0);
}

static void test_srvrun_wt_credit_after_quic_max_streams(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob                       = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c                        = crd_fixture(&f, &ob);
  c->s.sdrv.peer_initial_max_streams_uni = 0;
  c->peer_uni_stream_limit = c->wt_uni_opened + srvrun_uni_plumbing(c);
  CHECK(crd_open(c) == -1); /* RFC 9000 4.6: no uni credit */
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 0);
  c->peer_uni_stream_limit++; /* a MAX_STREAMS(uni) raise, applied */
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 1 && g_crd_last == &c->wt);
  CHECK(crd_open(c) > 0);
}

static void test_srvrun_wt_credit_without_callback(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob                 = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c                  = crd_fixture(&f, &ob);
  g_srvrun_env.wt_on_stream_credit = 0;
  CHECK(wired_wt_session_set_max_streams(&c->wt, 0, 1));
  CHECK(crd_open(c) > 0);
  CHECK(crd_open(c) == -1);
  CHECK(wired_wt_session_set_max_streams(&c->wt, 0, 2));
  srvrun_wt_credit_poll(&g_srvrun_env, c); /* no callback: no crash */
  CHECK(g_crd_calls == 0);
}

static i64 crd_open_bidi(srvrun_conn* c) {
  return wired_server_wt_open_bidi(
      &c->wt, wired_span_of(sr_wtsend_hello, sizeof sr_wtsend_hello));
}

static void test_srvrun_wt_credit_bidi(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c  = crd_fixture(&f, &ob);
  CHECK(wired_wt_session_set_max_streams(&c->wt, 1, 1));
  CHECK(crd_open_bidi(c) > 0);
  CHECK(crd_open_bidi(c) == -1);
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 0);
  CHECK(wired_wt_session_set_max_streams(&c->wt, 1, 2));
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 1);
  CHECK(crd_open_bidi(c) > 0);
}

static void test_srvrun_wt_credit_max_data(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob   = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c    = crd_fixture(&f, &ob);
  c->wt.flow_control = 1;
  CHECK(wired_wt_session_set_max_streams(&c->wt, 0, 100));
  CHECK(wired_wt_session_set_max_data(&c->wt, sizeof sr_wtsend_hello));
  CHECK(crd_open(c) > 0);
  CHECK(crd_open(c) == -1); /* WT_MAX_DATA used up */
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 0);
  CHECK(wired_wt_session_set_max_data(&c->wt, 2 * sizeof sr_wtsend_hello));
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 1);
  CHECK(crd_open(c) > 0);
}

/* Open until refused; returns the number that opened (bounded by the
 * table). */
static int crd_fill(srvrun_conn* c) {
  int n = 0;
  while (n <= (int)SRVRUN_WT_SEND_SLOTS && crd_open(c) > 0) {
    n++;
  }
  return n;
}

static void test_srvrun_wt_credit_share(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c  = crd_fixture(&f, &ob);
  CHECK(crd_fill(c) > 0); /* the last open hit the share */
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 0);
  c->wtsend[srvrun_wtsend_find(c, 15) - c->wtsend].in_use = 0;
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 1);
  CHECK(crd_open(c) > 0);
}

/* Every send slot held by an inactive session slot: the share check passes
 * but the claim fails. */
static void test_srvrun_wt_credit_table_full(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c  = crd_fixture(&f, &ob);
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    c->wtsend_free               = 0; /* in_use set by hand */
    c->wtsend[i].in_use          = 1;
    c->wtsend[i].wt_session_slot = 1;
  }
  CHECK(crd_open(c) == -1);
  CHECK(crd_open_bidi(c) == -1);
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 0); /* no slot is free yet */
  c->wtsend[3].in_use = 0;
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 1);
  CHECK(crd_open_bidi(c) > 0);
}

static void crd_reopen(void* ctx, wired_wt_session* s) {
  srvrun_conn* c = ctx;
  (void)s;
  g_crd_calls++;
  CHECK(crd_open(c) > 0);
  CHECK(crd_open(c) == -1); /* refused again: must re-arm */
}

static void test_srvrun_wt_credit_reopen_rearms(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob                  = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c                   = crd_fixture(&f, &ob);
  g_srvrun_env.wt_on_stream_credit  = crd_reopen;
  g_srvrun_env.wt_stream_credit_ctx = c;
  CHECK(wired_wt_session_set_max_streams(&c->wt, 0, 1));
  CHECK(crd_open(c) > 0);
  CHECK(crd_open(c) == -1);
  CHECK(wired_wt_session_set_max_streams(&c->wt, 0, 2));
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 1);
  CHECK(wired_wt_session_set_max_streams(&c->wt, 0, 3));
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 2);
  g_srvrun_env.wt_stream_credit_ctx = 0;
}

static void test_srvrun_wt_credit_closed_session(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c   = crd_fixture(&f, &ob);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  CHECK(wired_wt_session_set_max_streams(&c->wt, 0, 1));
  CHECK(crd_open(c) > 0);
  CHECK(crd_open(c) == -1);
  srvrun_close_wt_session_slot(&cfg, c, 0, 0);
  wired_wt_session_set_max_streams(&c->wt, 0, 2);
  srvrun_wt_credit_poll(&g_srvrun_env, c);
  CHECK(g_crd_calls == 0);
}

void test_srvrun_credit(void) {
  test_srvrun_wt_credit_no_block_no_call();
  test_srvrun_wt_credit_after_wt_max_streams();
  test_srvrun_wt_credit_after_quic_max_streams();
  test_srvrun_wt_credit_without_callback();
  test_srvrun_wt_credit_bidi();
  test_srvrun_wt_credit_max_data();
  test_srvrun_wt_credit_share();
  test_srvrun_wt_credit_table_full();
  test_srvrun_wt_credit_reopen_rearms();
  test_srvrun_wt_credit_closed_session();
  g_srvrun_env.wt_on_stream_credit = 0;
}
