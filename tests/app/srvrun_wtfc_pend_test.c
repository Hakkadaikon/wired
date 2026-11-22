/* @file
 * draft-ietf-webtrans-http3-16 5.4: the Stream Body bytes of a client
 * stream refused before its offer (a full WT bidi table, or a session that
 * rejected it) count against its session's data limit once the stream's
 * final size is known (RFC 9000 4.5), so the client's data credit is not
 * lost with it. Reuses srvrun_wtfc_test.c's fc_* fixtures, included earlier
 * in the same unity TU.
 *
 * Test list:
 * - a refused stream counts nothing until its final size is known, then
 *   exactly that size less its signal; WT_MAX_DATA rises by those bytes.
 * - 200 refusals of 10000-byte streams in a row never shrink the client's
 *   remaining data credit below half a window.
 * - a stream rejected at its offer counts its final size the same way.
 * - past SRVRUN_WTFC_PEND waiting streams, the extra ones are not counted
 *   (never more than the client sent). */

/* Client bidi stream id, refused for a full table, signal "40 41 04"
 * naming session 4, whose final size is then fixed at 3 + body. */
static void fc_refuse_with(srvrun_conn* c, u64 id, u64 body, int final) {
  wired_srvloop_rxacct* e;
  srvloop_wt_refuse_full(&c->l, id, 4, 3);
  c->l.wt_refused_n = 0; /* the refusal reset is not under test */
  e                 = srvloop_rxacct_entry(&c->l, id);
  CHECK(e != 0);
  if (final) {
    CHECK(finalsize_set(&e->fs, 3 + body));
  }
}

static void test_srvrun_wtfc_pend_refused_bytes_count(void) {
  struct lp_fix         f;
  u8                    obuf[1024];
  wired_obuf            ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg            cfg = sr_wt_send_cfg();
  srvrun_conn*          c   = fc_fixture(&f, &ob);
  u64                   w   = H3SETTINGS_WT_INIT_DATA_VALUE;
  int                   i   = fc_open(c, 1, 8);
  usz                   n;
  wired_srvloop_rxacct* e;
  fc_offer(&cfg, c);
  c->l.wt_streams[i].delivered_len = w / 2 - 1000;
  fc_refuse_with(c, 12, 1000, 0);
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wtx.fc[0].done == 0); /* final size not known yet */
  CHECK(fc_sent(c, 2, &n) == 0 && n == 0);
  e = srvloop_rxacct_entry(&c->l, 12);
  CHECK(e != 0 && finalsize_set(&e->fs, 1003));
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wtx.fc[0].done == 1000);
  CHECK(fc_sent(c, 2, &n) == w / 2 + w && n == 1);
}

static void test_srvrun_wtfc_pend_long_refusals_keep_credit(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob    = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg   = sr_wt_send_cfg();
  srvrun_conn*  c     = fc_fixture(&f, &ob);
  u64           w     = H3SETTINGS_WT_INIT_DATA_VALUE;
  u64           total = 0;
  for (u64 k = 0; k < 200; k++) {
    fc_refuse_with(c, 12 + 4 * k, 10000, 1);
    total += 10000;
    srvrun_wtfc_step(&cfg, c);
  }
  CHECK(c->wt_active == 1);
  CHECK(c->wtx.fc[0].done == total);
  CHECK(c->wtx.fc[0].max_data > total);
  CHECK(c->wtx.fc[0].max_data - total >= w / 2);
}

static void test_srvrun_wtfc_pend_rejected_bytes_count(void) {
  struct lp_fix         f;
  u8                    obuf[1024];
  wired_obuf            ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg            cfg = sr_wt_send_cfg();
  srvrun_conn*          c   = fc_fixture(&f, &ob);
  u64                   id  = 14 + 4 * WIRED_WT_MAX_BUFFERED_STREAMS;
  wired_srvloop_rxacct* e;
  c->wt.state = WIRED_WT_UNESTABLISHED; /* buffers, then rejects */
  for (u64 k = 0; k <= WIRED_WT_MAX_BUFFERED_STREAMS; k++) {
    fc_open(c, 0, 14 + 4 * k);
  }
  fc_offer(&cfg, c);
  c->wt.state = WIRED_WT_ESTABLISHED;
  e           = srvloop_rxacct_entry(&c->l, id);
  CHECK(e != 0 && finalsize_set(&e->fs, 3 + 500));
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wtx.fc[0].done == 500);
}

static void test_srvrun_wtfc_pend_overflow_never_over_counts(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  srvrun_conn*  c   = fc_fixture(&f, &ob);
  u64           all = SRVRUN_WTFC_PEND + 2;
  for (u64 k = 0; k < all; k++) {
    fc_refuse_with(c, 12 + 4 * k, 10, 0);
    if (k % 8 == 7) {
      srvrun_wtfc_step(&cfg, c); /* srvloop queues at most one step's */
    }
  }
  srvrun_wtfc_step(&cfg, c);
  for (u64 k = 0; k < all; k++) {
    wired_srvloop_rxacct* e = srvloop_rxacct_entry(&c->l, 12 + 4 * k);
    CHECK(e != 0 && finalsize_set(&e->fs, 3 + 10));
  }
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wtx.fc[0].done == 10 * SRVRUN_WTFC_PEND);
}

void test_srvrun_wtfc_pend(void) {
  test_srvrun_wtfc_pend_refused_bytes_count();
  test_srvrun_wtfc_pend_long_refusals_keep_credit();
  test_srvrun_wtfc_pend_rejected_bytes_count();
  test_srvrun_wtfc_pend_overflow_never_over_counts();
}
