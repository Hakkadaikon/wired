/* @file
 * WebTransport flow control, teardown, per-session resources of srvrun
 * (draft-ietf-webtrans-http3-16 4.4/4.8/5.6.5/6/8). Reuses srvrun_test.c's
 * fixtures (sr_wtsend_fixture, sr_wt_send_cfg), included earlier in the
 * same unity TU.
 *
 * Test list:
 * - exporter: equals RFC 8446 7.5 TLS-Exporter("EXPORTER-WebTransport",
 *   hand-serialized Exporter Context) over the live connection's secret;
 *   two sessions differ; SHA-384 suite uses SHA-384; no secret / no
 *   connection -> 0; label over 255 -> 0. */

/* RFC 8446 7.5 composed by hand over suite's hash: Derive-Secret(secret,
 * label, "") then HKDF-Expand-Label(.., "exporter", Hash(ctx), out.n). */
static void wtf_ref_exporter(
    u16 suite, const u8* secret, wired_span ctx, wired_mspan out) {
  const tls_hash* h = tls_hash_of(suite);
  u8              empty[TLS_HASH_MAX], derived[TLS_HASH_MAX], ch[TLS_HASH_MAX];
  hkdf_label      dl = {"EXPORTER-WebTransport", 21, {0, 0}};
  hkdf_label      el = {"exporter", 8, {0, 0}};
  h->digest((const u8*)"", 0, empty);
  dl.ctx = wired_span_of(empty, h->len);
  CHECK(h->expand_label(secret, &dl, wired_mspan_of(derived, h->len)));
  h->digest(ctx.p, ctx.n, ch);
  el.ctx = wired_span_of(ch, h->len);
  CHECK(h->expand_label(derived, &el, out));
}

/* The Exporter Context for session 4, label "lbl", context "ctx", written
 * out byte by byte (draft-ietf-webtrans-http3-16 4.8 Figure 6). */
static const u8 wtf_ctx4[] = {0, 0,   0,   0,   0, 0,   0,   4,
                              3, 'l', 'b', 'l', 3, 'c', 't', 'x'};

static void test_srvrun_wt_exporter_matches_tls_exporter(void) {
  struct lp_fix f;
  wired_obuf    ob = {0};
  u8            obuf[1024], got[40], want[40], other[40];
  srvrun_conn*  c;
  const u8*     secret;
  wired_span    lbl = wired_span_of((const u8*)"lbl", 3);
  wired_span    ctx = wired_span_of((const u8*)"ctx", 3);
  ob                = (wired_obuf){obuf, sizeof obuf, 0};
  c                 = sr_wtsend_fixture(&f, &ob);
  CHECK(keysched_exporter_secret(&c->s.sched, &secret));
  CHECK(
      wired_server_wt_exporter(
          &c->wt, lbl, ctx, wired_mspan_of(got, sizeof got)) == 1);
  wtf_ref_exporter(
      c->s.sched.suite, secret, wired_span_of(wtf_ctx4, sizeof wtf_ctx4),
      wired_mspan_of(want, sizeof want));
  CHECK(ct_diffn(got, want, sizeof got) == 0);
  /* a second session on the same connection gets its own material */
  wired_wt_session_init(&c->wt1, 8);
  c->wt1_active = 1;
  CHECK(
      wired_server_wt_exporter(
          &c->wt1, lbl, ctx, wired_mspan_of(other, sizeof other)) == 1);
  CHECK(ct_diffn(got, other, sizeof got) != 0);
}

/* TLS_AES_256_GCM_SHA384 runs the exporter over SHA-384 (RFC 8446 7.1). */
static void test_srvrun_wt_exporter_sha384_suite(void) {
  struct lp_fix f;
  wired_obuf    ob = {0};
  u8            obuf[1024], got[48], want[48];
  srvrun_conn*  c;
  u8            secret[48];
  wired_span    lbl = wired_span_of((const u8*)"lbl", 3);
  wired_span    ctx = wired_span_of((const u8*)"ctx", 3);
  ob                = (wired_obuf){obuf, sizeof obuf, 0};
  c                 = sr_wtsend_fixture(&f, &ob);
  c->s.sched.suite  = 0x1302;
  for (usz i = 0; i < sizeof secret; i++) {
    c->s.sched.exporter_secret[i] = secret[i] = (u8)(i * 7 + 1);
  }
  CHECK(
      wired_server_wt_exporter(
          &c->wt, lbl, ctx, wired_mspan_of(got, sizeof got)) == 1);
  wtf_ref_exporter(
      0x1302, secret, wired_span_of(wtf_ctx4, sizeof wtf_ctx4),
      wired_mspan_of(want, sizeof want));
  CHECK(ct_diffn(got, want, sizeof got) == 0);
}

/* No live connection, no exporter secret yet, or an over-long label. */
static void test_srvrun_wt_exporter_refusals(void) {
  struct lp_fix    f;
  wired_obuf       ob = {0};
  u8               obuf[1024], out[32], big[256] = {0};
  srvrun_conn*     c;
  wired_wt_session stray = {0};
  wired_span       e     = wired_span_of(0, 0);
  wired_mspan      o     = wired_mspan_of(out, sizeof out);
  ob                     = (wired_obuf){obuf, sizeof obuf, 0};
  c                      = sr_wtsend_fixture(&f, &ob);
  CHECK(wired_server_wt_exporter(&stray, e, e, o) == 0);
  CHECK(wired_server_wt_exporter(&c->wt, wired_span_of(big, 256), e, o) == 0);
  CHECK(wired_server_wt_exporter(&c->wt, wired_span_of(big, 255), e, o) == 1);
  c->s.sched.stage = 1;
  CHECK(wired_server_wt_exporter(&c->wt, e, e, o) == 0);
}

void test_srvrun_wtflow(void) {
  test_srvrun_wt_exporter_matches_tls_exporter();
  test_srvrun_wt_exporter_sha384_suite();
  test_srvrun_wt_exporter_refusals();
}
