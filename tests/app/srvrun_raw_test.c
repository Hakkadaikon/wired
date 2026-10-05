/* @file
 * Raw-QUIC (native QUIC) application connections in srvrun.c, ledger 13-6 /
 * RawQuic plan S9 (tasks/loopeng/moqt/RawQuic/plan.md §7.5, MoqtRawConn
 * TRACE.md T-E11..T-E12): an ALPN from wired_srvboot_id.raw_alpns gets one
 * implicit session at handshake confirmation (draft-ietf-moq-transport-19
 * 3.1.5 / -22 6.2.2) that carries the native-QUIC binding -- no HTTP/3
 * plumbing, uni ids from 3, unprefixed datagrams, verbatim reset codes, and
 * CONNECTION_CLOSE 0x1d as the session close (-19 3.5 / -22 6.6).
 * Reuses srvrun_test.c's fixtures (sr_make_confirmed_conn, sr_sl_step,
 * g_sl_*, sr_reset_global_table) and srvloop_test.c's lp_* client, both
 * included earlier in the same unity TU. */

#include "tls/ext/salpn/salpn_raw.h"

static const char g_srr_alpns[] = "moqt-22 moqt-19";

/* Event log: 'S' raw_on_session, 'D' stream data, 'G' datagram, 'R' reset,
 * 'C' session close -- in callback order. */
static char              g_srr_log[32];
static usz               g_srr_logn;
static wired_wt_session* g_srr_sess;
static wired_span        g_srr_tok;
static u8                g_srr_buf[64];
static usz               g_srr_len;
static u64               g_srr_id;
static int               g_srr_mapped;
static u32               g_srr_code;

static void srr_note(char e) {
  if (g_srr_logn < sizeof g_srr_log - 1) g_srr_log[g_srr_logn++] = e;
}

static int srr_log_is(const char* want) {
  usz n = wired_cstr_len(want);
  return n == g_srr_logn && !ct_diffn((const u8*)g_srr_log, (const u8*)want, n);
}

static void srr_keep(wired_span d) {
  g_srr_len = d.n < sizeof g_srr_buf ? d.n : sizeof g_srr_buf;
  bytes_memcpy(g_srr_buf, d.p, g_srr_len);
}

static void srr_on_session(void* ctx, wired_wt_session* s, wired_span alpn) {
  (void)ctx;
  g_srr_sess = s;
  g_srr_tok  = alpn;
  srr_note('S');
}

static void srr_on_data(
    void* ctx, wired_wt_session* s, u64 id, wired_span d, int fin) {
  (void)ctx;
  (void)s;
  (void)fin;
  g_srr_id = id;
  srr_keep(d);
  srr_note('D');
}

static void srr_on_dg(void* ctx, wired_wt_session* s, wired_span d) {
  (void)ctx;
  (void)s;
  srr_keep(d);
  srr_note('G');
}

static void srr_on_reset(
    void* ctx, wired_wt_session* s, u64 id, int mapped, u32 code) {
  (void)ctx;
  (void)s;
  g_srr_id     = id;
  g_srr_mapped = mapped;
  g_srr_code   = code;
  srr_note('R');
}

static void srr_on_close(void* ctx, wired_wt_session* s) {
  (void)ctx;
  (void)s;
  srr_note('C');
}

static void srr_reset_log(void) {
  g_srr_logn = 0;
  g_srr_sess = 0;
  g_srr_tok  = wired_span_of(0, 0);
  g_srr_len  = 0;
}

/* g_sl_cfg/g_sl_ctx over the global env's conns (the wired_server_* API
 * resolves sessions through it), with every recorder registered. */
static void srr_cfg(void) {
  g_sl_cfg                     = (srvrun_cfg){0};
  g_sl_cfg.fd                  = -1;
  g_sl_cfg.env                 = &g_srvrun_env;
  g_sl_cfg.handler             = sr_wt_handler;
  g_sl_cfg.wt_on_stream_data   = srr_on_data;
  g_sl_cfg.wt_on_datagram      = srr_on_dg;
  g_sl_cfg.wt_on_stream_reset  = srr_on_reset;
  g_sl_cfg.wt_on_session_close = srr_on_close;
  g_sl_st  = (srvrun_state){g_srvrun_table, g_srvrun_state.conns};
  g_sl_ctx = (srvrun_step_ctx){&g_sl_cfg, 0, &g_sl_st, 0, 0};
  g_sl_pn  = 10;
  g_srvrun_env.dgring_head     = 0;
  g_srvrun_env.dgring_n        = 0;
  g_srvrun_env.raw_on_session  = srr_on_session;
  g_srvrun_env.raw_session_ctx = 0;
  srr_reset_log();
}

/* A confirmed connection in slot 0 that negotiated alpn (tok "moqt-19" for
 * SALPN_RAW), not yet stepped: no session exists before its first step. */
static srvrun_conn* srr_fixture(salpn_choice alpn) {
  u8           obuf[1024];
  wired_obuf   ob = obuf_of(obuf, sizeof obuf);
  srvrun_conn* c  = &g_srvrun_state.conns[0];
  sr_reset_global_table();
  sr_make_confirmed_conn(c, &g_sl_f, &ob);
  srr_cfg();
  c->s.sdrv.alpn     = alpn;
  c->s.sdrv.alpn_tok = alpn == SALPN_RAW
                           ? wired_span_of((const u8*)g_srr_alpns + 8, 7)
                           : wired_span_of(0, 0);
  c->l.peer_ctrl.settings_seen = 0;
  /* the fixture confirmed as h3; a raw confirm sends no SETTINGS (T-E1) */
  c->l.h3.settings_sent                              = alpn == SALPN_H3;
  c->l.we_advertised_max_datagram                    = 100;
  c->s.sdrv.peer_initial_max_stream_data_uni         = 1u << 24;
  c->s.sdrv.peer_initial_max_stream_data_bidi_remote = 1u << 24;
  c->cc.cwnd                                         = 1u << 20;
  return c;
}

/* One client 1-RTT packet holding only PING (RFC 9000 19.2). */
static void srr_ping(srvrun_conn* c) {
  static const u8 ping[] = {0x01};
  sr_sl_step(c, ping, sizeof ping);
}

/* A raw connection stepped once: its implicit session exists. */
static srvrun_conn* srr_raw_live(void) {
  srvrun_conn* c = srr_fixture(SALPN_RAW);
  srr_ping(c);
  return c;
}

/* One client STREAM frame (id, offset 0, d) as its own packet. */
static void srr_stream(srvrun_conn* c, u64 id, const u8* d, usz n) {
  u8           pl[128];
  wired_obuf   sob = obuf_of(pl, sizeof pl);
  stream_frame sf  = {id, 0, n, d, 0};
  CHECK(appdata_stream_frame(&sf, &sob) == 1);
  sr_sl_step(c, pl, sob.len);
}

/* T-E8 first half / plan §4.4: the session is born at the first step after
 * confirmation, reported once with the ALPN token, established, flow
 * control off, and never re-created by a later step. */
static void test_srvrun_raw_session_at_confirm(void) {
  srvrun_conn* c = srr_fixture(SALPN_RAW);
  CHECK(c->wt_active == 0);
  srr_ping(c);
  CHECK(srr_log_is("S"));
  CHECK(g_srr_sess == &c->wt && c->wt_active == 1);
  CHECK(g_srr_tok.p == (const u8*)g_srr_alpns + 8 && g_srr_tok.n == 7);
  CHECK(c->wt.state == WIRED_WT_ESTABLISHED);
  CHECK(c->wt.connect_stream_id == RAWQ_NO_CONNECT_ID);
  CHECK(c->wt.flow_control == 0);
  CHECK(wired_server_session_is_raw(&c->wt) == 1);
  srr_ping(c);
  CHECK(srr_log_is("S"));
}

/* wired_server_session_is_raw: 0 for a WT session and a stale pointer. */
static void test_srvrun_raw_is_raw_query(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c  = sr_wtsend_fixture(&f, &ob);
  CHECK(wired_server_session_is_raw(&c->wt) == 0);
  c->wt_active = 0;
  CHECK(wired_server_session_is_raw(&c->wt) == 0);
}

/* T-E11 (SessOnlyOnApp): an hq-interop, an h3 and a no-ALPN connection get
 * no raw_on_session, however many steps run. */
static void test_srvrun_raw_no_session_off_raw(void) {
  static const salpn_choice other[] = {SALPN_HQ, SALPN_H3, SALPN_NONE};
  for (usz i = 0; i < sizeof other / sizeof *other; i++) {
    srvrun_conn* c = srr_fixture(other[i]);
    srr_ping(c);
    srr_ping(c);
    CHECK(g_srr_logn == 0);
    CHECK(c->wt_active == 0);
  }
}

/* T-E1 (NoH3OnRaw), srvrun half: no QPACK encoder stream, no SETTINGS
 * latch, no GOAWAY on a raw connection. */
static void test_srvrun_raw_no_h3_plumbing(void) {
  srvrun_conn* c = srr_raw_live();
  srr_ping(c);
  CHECK(c->l.h3.settings_sent == 0);
  CHECK(c->qenc_stream_opened == 0);
  CHECK(srvrun_wtsend_find(c, 3) == 0 && srvrun_wtsend_find(c, 7) == 0);
  CHECK(srvrun_goaway_applies(c) == 0);
}

/* T-E2 (RFC 9000 2.1, plan §3.4 S1): raw uni ids are 3, 7, 11; the peer's
 * uni grant counts only them (no plumbing streams): a grant of 2 admits
 * exactly two. */
static void test_srvrun_raw_uni_ids_from_3(void) {
  static const u8 p[]                    = {0x05};
  srvrun_conn*    c                      = srr_raw_live();
  c->s.sdrv.peer_initial_max_streams_uni = 2;
  CHECK(wired_server_wt_open_uni_stream(&c->wt, wired_span_of(p, 1)) == 3);
  CHECK(wired_server_wt_open_uni(&c->wt, wired_span_of(p, 1)) == 7);
  CHECK(wired_server_wt_open_uni_stream(&c->wt, wired_span_of(p, 1)) == -1);
  c->s.sdrv.peer_initial_max_streams_uni = 3;
  CHECK(wired_server_wt_open_uni_stream(&c->wt, wired_span_of(p, 1)) == 11);
}

/* T-E2 WT row: an h3 connection's first WT uni stream is still 11. */
static void test_srvrun_raw_wt_uni_still_11(void) {
  static const u8 p[] = {0x05};
  struct lp_fix   f;
  u8              obuf[1024];
  wired_obuf      ob = obuf_of(obuf, sizeof obuf);
  srvrun_conn*    c  = sr_wtsend_fixture(&f, &ob);
  CHECK(wired_server_wt_open_uni_stream(&c->wt, wired_span_of(p, 1)) == 11);
}

/* T-E3: a client uni stream `6f 00 ..` (a MoQT SETUP, -19 3.3) is delivered
 * whole, and a client bidi `03 ..` (SUBSCRIBE) likewise -- never to the h3
 * request path. */
static void test_srvrun_raw_streams_delivered_whole(void) {
  static const u8 setup[] = {0x6f, 0x00, 0x02, 0x01, 0x02};
  static const u8 sub[]   = {0x03, 0x00, 0x01, 0x07};
  srvrun_conn*    c       = srr_raw_live();
  srr_stream(c, 2, setup, sizeof setup);
  CHECK(srr_log_is("SD"));
  CHECK(g_srr_id == 2 && g_srr_len == sizeof setup);
  CHECK(!ct_diffn(g_srr_buf, setup, sizeof setup));
  srr_stream(c, 0, sub, sizeof sub);
  CHECK(srr_log_is("SDD"));
  CHECK(g_srr_id == 0 && g_srr_len == sizeof sub);
  CHECK(!ct_diffn(g_srr_buf, sub, sizeof sub));
  CHECK(g_sr_wt_handler_calls == 0);
}

/* A client 1-RTT packet holding one DATAGRAM frame (RFC 9221 4) with d. */
static void srr_datagram(srvrun_conn* c, const u8* d, usz n) {
  u8             pl[64];
  datagram_frame df   = {.length = n, .data = d};
  usz            plen = datagram_encode(wired_mspan_of(pl, sizeof pl), &df, 1);
  sr_sl_step(c, pl, plen);
}

/* T-E4 (-19 11.3, plan §3.4 S3): a raw DATAGRAM payload reaches the app
 * whole -- `00 05 'h' 'i'` would lose its first byte to a qsid on WT. */
static void test_srvrun_raw_datagram_rx_whole(void) {
  static const u8 p[] = {0x00, 0x05, 'h', 'i'};
  srvrun_conn*    c   = srr_raw_live();
  srr_datagram(c, p, sizeof p);
  CHECK(srr_log_is("SG"));
  CHECK(g_srr_len == sizeof p && !ct_diffn(g_srr_buf, p, sizeof p));
  CHECK(c->closing == 0);
}

/* T-E4 boundary: a raw payload that is not a valid qsid (a truncated
 * 2-byte varint) is still delivered, never an H3_DATAGRAM_ERROR close. */
static void test_srvrun_raw_datagram_rx_no_qsid_check(void) {
  static const u8 p[] = {0x40};
  srvrun_conn*    c   = srr_raw_live();
  srr_datagram(c, p, sizeof p);
  CHECK(srr_log_is("SG"));
  CHECK(c->closing == 0);
}

/* The kept CONNECTION_CLOSE frame (c->close_pl) equals want. */
static int srr_close_pl_is(const srvrun_conn* c, const u8* want, usz n) {
  return c->close_pln == n && !ct_diffn(c->close_pl, want, n);
}

/* T-E5 (pinned, RFC 9000 19.19; -19 3.5): close_session(3, "") on raw is
 * an application CONNECTION_CLOSE `1d 03 00`, the connection enters the
 * closing state and on_session_close fires once in the same step. */
static void test_srvrun_raw_close_session_frame(void) {
  static const u8 want[] = {0x1d, 0x03, 0x00};
  srvrun_conn*    c      = srr_raw_live();
  CHECK(wired_server_wt_close_session(&c->wt, 3, wired_span_of(0, 0)) == 1);
  srr_ping(c);
  CHECK(srr_close_pl_is(c, want, sizeof want));
  CHECK(c->closing == 1 && c->wt_active == 0);
  CHECK(srr_log_is("SC"));
  srr_ping(c); /* closing: answered with the same frame, nothing else */
  CHECK(srr_log_is("SC"));
  CHECK(srr_close_pl_is(c, want, sizeof want));
}

/* T-E5 (pinned): code 0x8 INVALID_PATH with reason "bad path". */
static void test_srvrun_raw_close_session_reason(void) {
  static const u8 want[] = {0x1d, 0x08, 0x08, 'b', 'a', 'd',
                            ' ',  'p',  'a',  't', 'h'};
  srvrun_conn*    c      = srr_raw_live();
  wired_server_wt_close_session(
      &c->wt, 8, wired_span_of((const u8*)"bad path", 8));
  srr_ping(c);
  CHECK(srr_close_pl_is(c, want, sizeof want));
}

/* T-E5 boundary: a reason longer than the close frame's room is cut at
 * SRVRUN_RAW_CLOSE_REASON_MAX, the frame still goes out. */
static void test_srvrun_raw_close_long_reason(void) {
  u8           r[200];
  srvrun_conn* c = srr_raw_live();
  bytes_memset(r, 'x', sizeof r);
  wired_server_wt_close_session(&c->wt, 1, wired_span_of(r, sizeof r));
  srr_ping(c);
  CHECK(c->closing == 1);
  CHECK(c->close_pln == 3 + SRVRUN_RAW_CLOSE_REASON_MAX);
  CHECK(c->close_pl[2] == SRVRUN_RAW_CLOSE_REASON_MAX);
}

/* The kept control packet whose frames start with type t, or 0. */
static const srvrun_rst* srr_kept(const srvrun_conn* c, u8 t) {
  for (usz i = 0; i < SRVRUN_RST_RETX; i++)
    if (c->rst[i].pln && c->rst[i].pl[0] == t) return &c->rst[i];
  return 0;
}

/* T-E6 (pinned, RFC 9000 19.4; -19 3.3.4): raw stream_reset(3, 0x1) is
 * RESET_STREAM `04 03 01 00` -- code verbatim, final size 0 (the queued byte
 * was never pumped). */
static void test_srvrun_raw_reset_code_verbatim(void) {
  static const u8   p[]    = {0x05};
  static const u8   want[] = {0x04, 0x03, 0x01, 0x00};
  srvrun_conn*      c      = srr_raw_live();
  const srvrun_rst* k;
  CHECK(wired_server_wt_open_uni_stream(&c->wt, wired_span_of(p, 1)) == 3);
  CHECK(wired_server_wt_stream_reset(&c->wt, 3, 1) == 1);
  srr_ping(c);
  k = srr_kept(c, 0x04);
  CHECK(k && k->pln == sizeof want && !ct_diffn(k->pl, want, sizeof want));
}

/* T-E6 WT row (pinned): the same reset on WT carries the 8-byte varint
 * 0x52e4a40fa8dc (draft-ietf-webtrans-http3-15 4.4: 0x52e4a40fa8db + 1). */
static void test_srvrun_raw_reset_code_wt_mapped(void) {
  static const u8   p[]    = {0x05};
  static const u8   want[] = {0x04, 0x0b, 0xc0, 0x00, 0x52, 0xe4,
                              0xa4, 0x0f, 0xa8, 0xdc, 0x00};
  struct lp_fix     f;
  u8                obuf[1024];
  wired_obuf        ob  = obuf_of(obuf, sizeof obuf);
  srvrun_conn*      c   = sr_wtsend_fixture(&f, &ob);
  srvrun_cfg        cfg = sr_wt_send_cfg();
  const srvrun_rst* k;
  CHECK(wired_server_wt_open_uni_stream(&c->wt, wired_span_of(p, 1)) == 11);
  CHECK(wired_server_wt_stream_reset(&c->wt, 11, 1) == 1);
  srvrun_drain_wt_stream_reset(&cfg, c);
  k = srr_kept(c, 0x04);
  CHECK(k && k->pln == sizeof want && !ct_diffn(k->pl, want, sizeof want));
}

/* T-E6 STOP_SENDING (RFC 9000 19.5): raw stream_stop(2, 0x12) is
 * `05 02 12`. */
static void test_srvrun_raw_stop_code_verbatim(void) {
  static const u8   want[] = {0x05, 0x02, 0x12};
  srvrun_conn*      c      = srr_raw_live();
  const srvrun_rst* k;
  CHECK(wired_server_wt_stream_stop(&c->wt, 2, 0x12) == 1);
  srr_ping(c);
  k = srr_kept(c, 0x05);
  CHECK(k && k->pln == sizeof want && !ct_diffn(k->pl, want, sizeof want));
}

/* T-E6 receive half (R12/R13): a peer RESET_STREAM 0x12 on a raw uni
 * stream reaches the app mapped with 0x12; 2^32 is unmapped. */
static void test_srvrun_raw_reset_in(void) {
  static const u8  d[]    = {0x6f, 0x00};
  static const u64 wire[] = {0x12, 1ull << 32};
  static const int mapd[] = {1, 0};
  for (usz i = 0; i < 2; i++) {
    srvrun_conn*       c = srr_raw_live();
    u8                 pl[32];
    reset_stream_frame rs = {2, wire[i], 2};
    srr_stream(c, 2, d, sizeof d);
    sr_sl_step(c, pl, reset_stream_encode(pl, sizeof pl, &rs));
    CHECK(srr_log_is("SDR"));
    CHECK(g_srr_id == 2 && g_srr_mapped == mapd[i]);
    CHECK(!mapd[i] || g_srr_code == 0x12);
  }
}

/* T-E7 (pinned, -19 11.3): a raw datagram send queues P itself; on WT the
 * ring entry is qsid(0) = `00` followed by P (RFC 9297 2.1). */
static void test_srvrun_raw_datagram_tx_unprefixed(void) {
  static const u8      p[] = {0xaa, 0xbb, 0xcc};
  srvrun_conn*         c   = srr_raw_live();
  srvrun_dgring_entry* e   = &g_srvrun_env.dgring[g_srvrun_env.dgring_head];
  CHECK(wired_server_wt_send_datagram_to(&c->wt, wired_span_of(p, 3)) == 1);
  CHECK(e->len == 3 && !ct_diffn(e->buf, p, 3));
}

static void test_srvrun_raw_datagram_tx_wt_prefixed(void) {
  static const u8      p[]    = {0xaa, 0xbb, 0xcc};
  static const u8      want[] = {0x00, 0xaa, 0xbb, 0xcc};
  struct lp_fix        f;
  u8                   obuf[1024];
  wired_obuf           ob = obuf_of(obuf, sizeof obuf);
  srvrun_conn*         c  = sr_wtsend_fixture(&f, &ob);
  srvrun_dgring_entry* e  = &g_srvrun_env.dgring[g_srvrun_env.dgring_head];
  wired_wt_session_init(&c->wt, 0);
  wired_wt_session_establish(&c->wt);
  c->l.h3.settings_sent = 1;
  CHECK(wired_server_wt_send_datagram_to(&c->wt, wired_span_of(p, 3)) == 1);
  CHECK(e->len == 4 && !ct_diffn(e->buf, want, 4));
}

/* T-E8: a peer CONNECTION_CLOSE ends the raw session once (CloseOnce). */
static void test_srvrun_raw_peer_close_once(void) {
  static const u8  why[] = "bye";
  srvrun_conn*     c     = srr_raw_live();
  conn_close_frame cc    = {1, 0, 0, 3, why};
  u8               pl[32], spkt[256];
  usz              pln = frame_put_conn_close(pl, sizeof pl, &cc);
  usz              slen =
      client_seal_onertt_pn(&g_sl_f, g_sl_pn++, pl, pln, spkt, sizeof spkt);
  srvrun_step_and_reap(&g_sl_ctx, 0, wired_mspan_of(spkt, slen));
  CHECK(c->up == 0);
  CHECK(srr_log_is("SC"));
}

/* T-E8: the idle sweep ends the raw session once; the reused slot gets a
 * fresh raw_on_session (NoGhost). */
static void test_srvrun_raw_idle_close_then_reuse(void) {
  srvrun_conn* c = srr_raw_live();
  srvrun_sweep_idle(&g_sl_cfg, &g_sl_st, c->last_ms + WIRED_SRVRUN_IDLE_MS);
  CHECK(c->up == 0);
  CHECK(srr_log_is("SC"));
  c = srr_raw_live();
  CHECK(srr_log_is("S"));
  CHECK(c->wt_active == 1);
}

/* T-E10 (plan §3.4 S9): a confirmed raw connection is never "boot
 * overdue". */
static void test_srvrun_raw_not_boot_overdue(void) {
  srvrun_conn* c = srr_raw_live();
  CHECK(srvrun_boot_overdue(c, c->boot_claim_ms + 10 * 60 * 1000) == 0);
}

/* R15: raw QUIC has no transport-level drain -- drain_session refuses
 * instead of putting a capsule on the sentinel CONNECT id. */
static void test_srvrun_raw_no_drain(void) {
  srvrun_conn* c = srr_raw_live();
  CHECK(wired_server_wt_drain_session(&c->wt) == 0);
  CHECK(srvrun_wtsend_find(c, RAWQ_NO_CONNECT_ID) == 0);
}

/* S7 note: a client bidi refused for a full wt_streams[] table is reset
 * with a MoQT code (EXCESSIVE_LOAD 0x9, -19 3.3.4), not an HTTP/3 one. */
static void test_srvrun_raw_refuse_code(void) {
  static const u8   want[] = {0x04, 0x00, 0x09, 0x00, 0x05, 0x00, 0x09};
  srvrun_conn*      c      = srr_raw_live();
  const srvrun_rst* k;
  c->l.wt_refused[0] = 0;
  c->l.wt_refused_n  = 1;
  srvrun_refuse_wt_streams(&g_sl_cfg, c);
  k = srr_kept(c, 0x04);
  CHECK(k && k->pln == sizeof want && !ct_diffn(k->pl, want, sizeof want));
}

/* plan open question 4 / K3: every client uni stream the advertised limit
 * admits has a reassembly slot on raw too (no stream lands nowhere). */
static void test_srvrun_raw_uni_capacity(void) {
  static const u8 d[] = {0x6f};
  srvrun_conn*    c   = srr_raw_live();
  u64             n   = wired_srvloop_uni_stream_limit();
  CHECK(WIRED_SRVLOOP_MAX_WT_UNI_STREAMS >= n);
  for (u64 i = 0; i < n; i++) srr_stream(c, 2 + 4 * i, d, 1);
  CHECK(g_srr_logn == 1 + n);
}

/* plan open question 3 / K5: raw sends stay inside the peer's QUIC
 * MAX_DATA -- the pump never consumes past conn_credit. */
static void test_srvrun_raw_conn_credit_enforced(void) {
  static u8    big[8000];
  srvrun_conn* c = srr_raw_live();
  c->conn_credit = 2000;
  CHECK(
      wired_server_wt_open_uni_stream(&c->wt, wired_span_of(big, sizeof big)) ==
      3);
  srvrun_sess_on_step(&g_sl_ctx, 0);
  srvrun_acct_resync(c);
  CHECK(c->acct_consumed > 0);
  CHECK(c->acct_consumed <= c->conn_credit);
}

/* ---- real TLS: the client offers only a raw id, negotiated by sdrv ---- */

/* lp_drive_to_flight with raw_alpns configured, the ClientHello's one ALPN
 * entry "h3" rewritten in place to "m9" (same length). */
static void srr_lp_raw_flight(struct lp_fix* f) {
  static const char list[] = "moqt-19 m9";
  u8                srv_priv[32], srv_pub[32], seed[32];
  wired_span        ext = {0, 0};
  bytes_memset(&f->s, 0, sizeof f->s);
  bytes_memset(&f->l, 0, sizeof f->l);
  lp_make_client_hello(f);
  CHECK(salpn_find_extension(
      wired_span_of(f->ch, f->ch_len), SALPN_EXT_TYPE, &ext));
  f->ch[(usz)(ext.p - f->ch) + 3] = 'm';
  f->ch[(usz)(ext.p - f->ch) + 4] = '9';
  for (usz i = 0; i < 32; i++) {
    srv_priv[i] = (u8)(0x40 + i);
    seed[i]     = (u8)(0x80 + i);
  }
  wired_x25519_base(srv_pub, srv_priv);
  {
    wired_server_init_in sin   = {srv_priv, srv_pub, seed, 0, 0, 0, 0, 0};
    wired_obuf           sh_ob = obuf_of(f->sh, sizeof f->sh);
    wired_obuf           fl_ob = obuf_of(f->flight, sizeof f->flight);
    sdrv_flight_out      fo    = {&sh_ob, &fl_ob};
    wired_server_init(&f->s, &sin);
    sdrv_set_raw_alpns(&f->s.sdrv, list);
    CHECK(
        wired_server_set_cids(
            &f->s, wired_span_of(g_cli_scid, 6),
            wired_span_of(g_cli_scid, 6)) == 1);
    CHECK(wired_srvloop_init(&f->l, g_cli_scid, 6) == 1);
    CHECK(wired_server_recv_initial(&f->s, f->ch, f->ch_len) == 1);
    CHECK(wired_server_build_flight(&f->s, f->srv_random, &fo) == 1);
    f->sh_len     = sh_ob.len;
    f->flight_len = fl_ob.len;
  }
  CHECK(f->s.sdrv.alpn == SALPN_RAW);
  CHECK(f->s.sdrv.alpn_tok.n == 2 && f->s.sdrv.alpn_tok.p[0] == 'm');
  lp_make_client_finished(f);
}

/* wired_server keeps pointers into its own storage (srvfin_state_init's
 * sched/keys); a by-value copy must point them at the copy, or its steps
 * advance the original's key schedule. */
static void srr_rebind(wired_server* s) {
  s->fin.sched = &s->sched;
  s->fin.keys  = &s->keys;
}

/* The client's 1-RTT keys exist only once the server has verified its
 * Finished: a twin of f confirms on a copy of the Handshake packet, and its
 * schedule seals the 1-RTT half (f itself is untouched). */
static struct lp_fix g_srr_twin;

static void srr_twin_confirm(const struct lp_fix* f, const u8* hs, usz hn) {
  u8         pkt[512], out[1500];
  wired_obuf ob = obuf_of(out, sizeof out);
  g_srr_twin    = *f;
  srr_rebind(&g_srr_twin.s);
  bytes_memcpy(pkt, hs, hn);
  wired_srvloop_step(
      &(wired_srvloop_conn){&g_srr_twin.l, &g_srr_twin.s},
      wired_mspan_of(pkt, hn), &ob);
  CHECK(wired_server_is_confirmed(&g_srr_twin.s) == 1);
}

/* One datagram: the client Finished (Handshake) coalesced with a 1-RTT
 * packet carrying a SETUP-shaped uni stream 2 (RFC 9000 12.2). */
static usz srr_finished_plus_setup(struct lp_fix* f, u8* dg, usz cap) {
  static const u8 setup[] = {0x6f, 0x00, 0x01, 0x00};
  u8              pl[64], hs[512], one[512];
  wired_obuf      sob = obuf_of(pl, sizeof pl);
  stream_frame    sf  = {2, 0, sizeof setup, setup, 0};
  usz             hn, on;
  CHECK(appdata_stream_frame(&sf, &sob) == 1);
  hn = client_seal_handshake(f, f->cli_fin, f->cli_fin_len, hs, sizeof hs);
  srr_twin_confirm(f, hs, hn);
  on = client_seal_onertt_pn(&g_srr_twin, 0, pl, sob.len, one, sizeof one);
  CHECK(hn + on <= cap);
  bytes_memcpy(dg, hs, hn);
  bytes_memcpy(dg + hn, one, on);
  return hn + on;
}

/* T-E12 / T-L1 (transport half; the hub half waits for S10): a real
 * raw-ALPN handshake whose Finished arrives coalesced with the client's
 * SETUP -- raw_on_session then the stream data fire in that ONE step
 * (SessBeforeData, D3), with no second datagram. */
static void test_srvrun_raw_coalesced_finished_setup(void) {
  static struct lp_fix f;
  u8                   dg[1400];
  srvrun_conn*         c = &g_srvrun_state.conns[0];
  usz                  n;
  sr_reset_global_table();
  srr_cfg();
  srr_lp_raw_flight(&f);
  n    = srr_finished_plus_setup(&f, dg, sizeof dg);
  c->s = f.s;
  c->l = f.l;
  srr_rebind(&c->s);
  c->up = 1;
  cc_init(&c->cc);
  rtt_init(&c->rtt);
  c->conn_credit = c->s.sdrv.peer_initial_max_data;
  CHECK(wired_server_is_confirmed(&c->s) == 0);
  srvrun_on_step(&g_sl_ctx, c, wired_mspan_of(dg, n));
  CHECK(wired_server_is_confirmed(&c->s) == 1);
  CHECK(srr_log_is("SD"));
  CHECK(g_srr_tok.n == 2 && g_srr_tok.p[0] == 'm' && g_srr_tok.p[1] == '9');
  CHECK(g_srr_id == 2 && g_srr_len == 4 && g_srr_buf[0] == 0x6f);
}

/* T-E1 (wire bytes): the same coalesced datagram through srvloop alone --
 * the server's 1-RTT reply carries HANDSHAKE_DONE and no STREAM frame on
 * the H3 control (3) or QPACK (7) stream. */
static void test_srvrun_raw_reply_has_no_settings(void) {
  static struct lp_fix f;
  u8                   dg[1400], out[1500];
  wired_obuf           ob = obuf_of(out, sizeof out);
  const u8 *           pkts[4], *pl;
  usz                  offs[4], lens[4], np, pll, n;
  framewalk            it;
  framewalk_item       fr;
  int                  done = 0, h3 = 0;
  srr_lp_raw_flight(&f);
  n = srr_finished_plus_setup(&f, dg, sizeof dg);
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f.l, &f.s}, wired_mspan_of(dg, n), &ob) == 1);
  {
    pktlist plist = {pkts, offs, lens, 4};
    np            = udploop_split(wired_span_of(out, ob.len), &plist);
  }
  CHECK(np == 2);
  CHECK(client_open_onertt(&f, out + offs[1], lens[1], &pl, &pll) == 1);
  framewalk_init(&it, pl, pll);
  while (framewalk_next(&it, &fr)) {
    stream_frame sf;
    done |= fr.type == 0x1e;
    if (fr.type >= 0x08 && fr.type <= 0x0f &&
        frame_get_stream(fr.start, fr.remaining, &sf))
      h3 |= (sf.stream_id & 3) == 3;
  }
  CHECK(done == 1);
  CHECK(h3 == 0);
}

void test_srvrun_raw(void) {
  test_srvrun_raw_session_at_confirm();
  test_srvrun_raw_is_raw_query();
  test_srvrun_raw_no_session_off_raw();
  test_srvrun_raw_no_h3_plumbing();
  test_srvrun_raw_uni_ids_from_3();
  test_srvrun_raw_wt_uni_still_11();
  test_srvrun_raw_streams_delivered_whole();
  test_srvrun_raw_datagram_rx_whole();
  test_srvrun_raw_datagram_rx_no_qsid_check();
  test_srvrun_raw_close_session_frame();
  test_srvrun_raw_close_session_reason();
  test_srvrun_raw_close_long_reason();
  test_srvrun_raw_reset_code_verbatim();
  test_srvrun_raw_reset_code_wt_mapped();
  test_srvrun_raw_stop_code_verbatim();
  test_srvrun_raw_reset_in();
  test_srvrun_raw_datagram_tx_unprefixed();
  test_srvrun_raw_datagram_tx_wt_prefixed();
  test_srvrun_raw_peer_close_once();
  test_srvrun_raw_idle_close_then_reuse();
  test_srvrun_raw_not_boot_overdue();
  test_srvrun_raw_no_drain();
  test_srvrun_raw_refuse_code();
  test_srvrun_raw_uni_capacity();
  test_srvrun_raw_conn_credit_enforced();
  test_srvrun_raw_coalesced_finished_setup();
  test_srvrun_raw_reply_has_no_settings();
  g_srvrun_env.raw_on_session = 0;
}
