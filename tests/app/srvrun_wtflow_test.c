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
 *   connection -> 0; label over 255 -> 0.
 * - WT_DATA_BLOCKED: an open or a stream send refused by the session data
 *   limit puts WT_DATA_BLOCKED(limit) on the CONNECT stream; a second
 *   refusal at the same limit sends nothing more; a raised limit that
 *   blocks again sends one naming the new limit; a send within the limit
 *   sends none. */

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

/* Every WT_DATA_BLOCKED value DATA-framed on w's CONNECT-stream bytes, in
 * order, into lim[]; returns how many (other capsules are skipped). */
static usz wtf_data_blocked_sent(const srvrun_wtsend* w, u64* lim, usz cap) {
  wired_span all = wired_span_of(w->roundbuf, w->sess.q.len);
  usz        off = 0, k = 0;
  while (off < all.n && k < cap) {
    h3_frame fr;
    usz      n  = h3_frame_get(wired_span_of(all.p + off, all.n - off), &fr);
    usz      at = 0;
    CHECK(n != 0);
    if (n == 0) {
      return k;
    }
    k += wtcapsule_decode_data_blocked(
             wired_span_of(fr.payload, fr.payload_len), &at, &lim[k]) == 1;
    off += n;
  }
  return k;
}

static void test_srvrun_wt_data_limited_send_emits_data_blocked_once(void) {
  struct lp_fix   f;
  wired_obuf      ob = {0};
  u8              obuf[1024];
  static const u8 pay[] = {0x54, 0x04, 'h', 'i'};
  wired_span      p     = wired_span_of(pay, sizeof pay);
  srvrun_conn*    c;
  u64             lim[4];
  i64             id;
  ob                 = (wired_obuf){obuf, sizeof obuf, 0};
  c                  = sr_wtsend_fixture(&f, &ob);
  c->wt.flow_control = 1;
  CHECK(wired_wt_session_set_max_streams(&c->wt, 0, 10) == 1);
  CHECK(wired_wt_session_set_max_data(&c->wt, 6) == 1);
  id = wired_server_wt_open_uni_stream(&c->wt, p); /* 4 of 6 bytes */
  CHECK(id == 15);
  CHECK(srvrun_wtsend_find(c, 4) == 0); /* within the limit: nothing */
  CHECK(wired_server_wt_stream_send(&c->wt, (u64)id, p, 0) <= 0);
  CHECK(wired_server_wt_open_uni_stream(&c->wt, p) == -1);
  CHECK(srvrun_wtsend_find(c, 4) != 0);
  CHECK(wtf_data_blocked_sent(srvrun_wtsend_find(c, 4), lim, 4) == 1);
  CHECK(lim[0] == 6);
  CHECK(wired_wt_session_set_max_data(&c->wt, 7) == 1);
  CHECK(wired_server_wt_stream_send(&c->wt, (u64)id, p, 0) <= 0);
  CHECK(wtf_data_blocked_sent(srvrun_wtsend_find(c, 4), lim, 4) == 2);
  CHECK(lim[1] == 7);
}

void test_srvrun_wtflow(void) {
  test_srvrun_wt_data_limited_send_emits_data_blocked_once();
  test_srvrun_wt_exporter_matches_tls_exporter();
  test_srvrun_wt_exporter_sha384_suite();
  test_srvrun_wt_exporter_refusals();
}
