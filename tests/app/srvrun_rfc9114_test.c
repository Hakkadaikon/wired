#include "test.h"

/* RFC 9110 / RFC 9114 rows pinned on the server's shipping path: client
 * packets sealed for real and stepped through srvrun_on_step +
 * srvrun_sess_on_step (the sr_sl_* fixture, srvrun_test.c), what the
 * server sends read back off a loopback socket (sr_net, rfcpin_wire_*).
 * Shared rfch3_* helpers live in srvrun_test.c. */

/* RFC 9110 6.5.1 (9110-035): a request's trailer fields are not merged
 * into its header section. A POST with header x-lead, a 3-byte body and a
 * trailer section carrying x-trail reaches the handler with exactly one
 * regular header (x-lead) and x-trail not found by name. */
static void test_srvrun_rfc9110_trailers_not_in_headers(void) {
  static const char* const lead[]  = {"x-lead", "a"};
  static const char* const trail[] = {"x-trail", "b"};
  sr_net                   n;
  srvrun_conn*             c = rfch3_fixture(&n);
  u8                       fs[128], tfs[64], req[512];
  wired_obuf               fob = obuf_of(fs, sizeof fs);
  wired_obuf               tob = obuf_of(tfs, sizeof tfs);
  usz                      len = 0;
  rfch3_fields(&fob, "POST", lead, 1);
  tfs[0]  = 0x00; /* RFC 9204 4.5.1: Required Insert Count 0, Base 0 */
  tfs[1]  = 0x00;
  tob.len = 2;
  rfch3_literal(&tob, trail[0], trail[1]);
  rfch3_frame(
      req, sizeof req, &len, H3_FRAME_HEADERS, wired_span_of(fs, fob.len));
  rfch3_frame(
      req, sizeof req, &len, H3_FRAME_DATA, wired_span_of((const u8*)"abc", 3));
  rfch3_frame(
      req, sizeof req, &len, H3_FRAME_HEADERS, wired_span_of(tfs, tob.len));
  g_rfch3_probe = "x-trail";
  rfch3_send_stream(c, 0, 0, req, len, 1);
  CHECK(g_rfch3.calls == 1);
  CHECK(g_rfch3.body_len == 3);
  CHECK(g_rfch3.n == 1 && rfch3_hdr_is(0, "x-lead", "a"));
  CHECK(g_rfch3.probe_found == 0);
  sr_net_close(&n);
}

/* RFC 9114 4.1.1 (9114-013): H3_REQUEST_REJECTED is only for a request the
 * application never saw. Stream 0 is answered; stream 4 is answered and
 * then stopped by the client (STOP_SENDING, H3_REQUEST_CANCELLED); a
 * GOAWAY goes out; stream 8, past it, is refused. On the wire stream 8's
 * RESET_STREAM carries H3_REQUEST_REJECTED, and no RESET_STREAM for 0 or
 * 4 does. */
static void test_srvrun_rfc9114_rejected_only_unseen(void) {
  static rfcpin_wire w;
  sr_net             n;
  srvrun_conn*       c = rfch3_fixture(&n);
  u8                 fr[64], out[256];
  wired_obuf         gob = obuf_of(out, sizeof out);
  stop_sending_frame ss  = {4, H3_REQUEST_CANCELLED};
  sr_sl_send_headers(c, 0, "GET", 1);
  sr_sl_send_headers(c, 4, "GET", 1);
  CHECK(g_rfch3.calls == 2);
  sr_sl_step(c, fr, stop_sending_encode(fr, sizeof fr, &ss));
  CHECK(srvrun_send_goaway(&g_sl_cfg, c, &gob) == 1);
  sr_sl_send_headers(c, 8, "GET", 1);
  CHECK(g_rfch3.calls == 2);
  rfch3_wire(&w, &n);
  CHECK(rfcpin_wire_reset_code(&w, 8) == H3_REQUEST_REJECTED);
  CHECK(rfcpin_wire_reset_code(&w, 4) == H3_REQUEST_CANCELLED);
  for (usz i = 0; i < w.rst_n; i++) {
    CHECK(w.rst_id[i] == 8 || w.rst_code[i] != H3_REQUEST_REJECTED);
  }
  sr_net_close(&n);
}

/* POST HEADERS with content-length: cl, then a DATA frame of n bytes. */
static usz rfch3_cl_head(u8* out, usz cap, const char* cl, usz n) {
  static const u8   body[64] = {0};
  const char* const nv[]     = {"content-length", cl};
  u8                fs[128];
  wired_obuf        fob = obuf_of(fs, sizeof fs);
  usz               len = 0;
  rfch3_fields(&fob, "POST", nv, 1);
  rfch3_frame(out, cap, &len, H3_FRAME_HEADERS, wired_span_of(fs, fob.len));
  rfch3_frame(out, cap, &len, H3_FRAME_DATA, wired_span_of(body, n));
  return len;
}

/* RFC 9114 4.1.2 (9114-015): a request found malformed while its body is
 * streaming to on_body is a stream error of type H3_MESSAGE_ERROR. A POST
 * declaring content-length 5 delivers its first 5 body bytes to on_body;
 * a second DATA frame then takes the body past 5. The server resets the
 * stream with H3_MESSAGE_ERROR on the wire, the handler never runs, the
 * body never reaches fin, and the connection stays up. */
static void test_srvrun_rfc9114_malformed_mid_body_message_error(void) {
  static rfcpin_wire w;
  sr_net             n;
  srvrun_conn*       c = rfch3_fixture(&n);
  u8                 req[256], more[16];
  usz                len = rfch3_cl_head(req, sizeof req, "5", 5), mlen = 0;
  g_sr_body    = (sr_body_rec){0};
  c->l.on_body = sr_on_body;
  rfch3_send_stream(c, 0, 0, req, len, 0);
  CHECK(g_sr_body.got_n == 5 && g_sr_body.fins == 0);
  rfch3_frame(
      more, sizeof more, &mlen, H3_FRAME_DATA,
      wired_span_of((const u8*)"xxxxx", 5));
  rfch3_send_stream(c, 0, len, more, mlen, 1);
  rfch3_wire(&w, &n);
  CHECK(rfcpin_wire_reset_code(&w, 0) == H3_MESSAGE_ERROR);
  CHECK(g_sr_body.fins == 0 && g_rfch3.calls == 0);
  CHECK(!c->closing);
  sr_net_close(&n);
}

/* The client acknowledges every packet the server sent from pn lo on, at
 * now (ms). */
static void rfch3_ack_all(srvrun_conn* c, u64 lo, u64 now) {
  g_sl_ctx.now_ms = now;
  c->l.now_ms     = now;
  sr_sl_ack_from(c, lo);
}

/* RFC 9114 5.1 (9114-089): no keep-alive on an idle connection. A GET is
 * answered; for the first two seconds of poll ticks (srvrun_fire_ptos) the
 * client acknowledges whatever arrives (the response, the owed ACK, the
 * MAX_STREAMS returning the request's credit). After that, with nothing
 * left unacknowledged, every tick up to just before the idle timeout sends
 * nothing at all -- no PING, no probe -- and the connection is still up. */
static void test_srvrun_rfc9114_idle_no_keepalive(void) {
  sr_net       n;
  srvrun_conn* c = rfch3_fixture(&n);
  conntable    table[WIRED_CONNTABLE_CAP];
  u8           pkt[PMTU_MAX];
  int          sent = 0;
  u64          lo   = c->l.tx_pn;
  conntable_init(table, WIRED_CONNTABLE_CAP);
  g_sl_st.table            = table;
  g_srvrun_env.step_now_on = 1;
  sr_sl_send_headers(c, 0, "GET", 1);
  CHECK(g_rfch3.calls == 1);
  for (u64 t = 0; t <= 2000; t += 100) {
    g_srvrun_env.step_now_ms = t;
    srvrun_fire_ptos(&g_sl_cfg, &g_sl_st);
    if (rfcpin_recv(n.afd, pkt)) {
      while (rfcpin_recv(n.afd, pkt)) {
      }
      rfch3_ack_all(c, lo, t);
    }
  }
  CHECK(c->resp[0].in_use == 0);
  for (u64 t = 2100; t < WIRED_SRVRUN_IDLE_MS; t += 100) {
    g_srvrun_env.step_now_ms = t;
    srvrun_fire_ptos(&g_sl_cfg, &g_sl_st);
    while (rfcpin_recv(n.afd, pkt)) {
      sent++;
    }
  }
  CHECK(sent == 0);
  CHECK(c->up == 1 && !c->closing);
  g_srvrun_env.step_now_on = 0;
  g_sl_st.table            = 0;
  sr_net_close(&n);
}

/* 1 if w carries any STREAM frame on a server-initiated bidi stream
 * (RFC 9000 2.1: id 1 mod 4). */
static int rfch3_server_bidi_sent(const rfcpin_wire* w) {
  for (usz i = 0; i < w->n; i++) {
    if (w->s[i].id % 4 == 1) {
      return 1;
    }
  }
  return 0;
}

/* RFC 9114 6.1 (9114-043): the server opens no bidirectional stream
 * outside a negotiated extension (an established WebTransport session).
 * GETs on 0 and 8 are answered, a session on 4 is established and closed
 * by the client; opening a bidi stream on that closed session, and on a
 * session no connection owns, is refused, and nothing on the wire uses a
 * server bidi id. The control: on an established session the same call
 * opens stream 1 and it goes out. */
static void test_srvrun_rfc9114_no_server_bidi_outside_session(void) {
  static const u8    pay[] = {0x41, 0x04, 'x'};
  static rfcpin_wire w;
  sr_net             n;
  srvrun_conn*       c = rfch3_fixture(&n);
  wired_wt_session   ghost;
  usz                hlen;
  u8                 cap[32];
  wired_obuf         cb = obuf_of(cap, sizeof cap);
  sr_sl_send_headers(c, 0, "GET", 1);
  hlen = sr_sl_send_headers(c, 4, "CONNECT", 0);
  CHECK(c->wt_active == 1);
  CHECK(wired_wtcapsule_encode_close(&cb, 0, wired_span_of(pay, 0)) == 1);
  sr_h3data(&cb, 0);
  rfch3_send_stream(c, 4, hlen, cap, cb.len, 0);
  CHECK(g_sl_closes == 1 && c->wt_active == 0);
  sr_sl_send_headers(c, 8, "GET", 1);
  CHECK(wired_server_wt_open_bidi(&c->wt, wired_span_of(pay, 3)) < 0);
  wired_wt_session_init(&ghost, 99);
  wired_wt_session_establish(&ghost);
  CHECK(wired_server_wt_open_bidi(&ghost, wired_span_of(pay, 3)) < 0);
  srvrun_sess_on_step(&g_sl_ctx, 0);
  rfch3_wire(&w, &n);
  CHECK(!rfch3_server_bidi_sent(&w));
  sr_net_close(&n);
  c = rfch3_fixture(&n);
  sr_sl_send_headers(c, 0, "CONNECT", 0);
  CHECK(wired_server_wt_open_bidi(&c->wt, wired_span_of(pay, 3)) == 1);
  srvrun_sess_on_step(&g_sl_ctx, 0);
  rfch3_wire(&w, &n);
  CHECK(rfch3_server_bidi_sent(&w));
  sr_net_close(&n);
}

/* 1 if w carries a server uni stream (id 3 mod 4) other than the control
 * and QPACK streams the server opens itself (3, 7, 11). */
static int rfch3_app_uni_sent(const rfcpin_wire* w) {
  for (usz i = 0; i < w->n; i++) {
    u64 id = w->s[i].id;
    if (id % 4 == 3 && id > SRVRUN_QDEC_STREAM && w->s[i].end) {
      return 1;
    }
  }
  return 0;
}

/* RFC 9114 6.2 / 9 (9114-091): a stream type that changes the protocol's
 * state (a WebTransport uni stream, type 0x54) is not sent before the
 * peer's SETTINGS show support. A CONNECT arrives before the client's
 * SETTINGS: it is held, no session exists, and opening a WebTransport uni
 * stream is refused -- the server sends no uni stream beyond its control
 * and QPACK streams. Once SETTINGS arrive the session is established and
 * the same open goes out on a new uni stream. The payload is a bare 'x'
 * (the app supplies the 0x54 signal; the SDK sends the bytes verbatim),
 * so only the stream itself, not its first byte, shows on the wire. */
static void test_srvrun_rfc9114_no_wt_uni_before_peer_settings(void) {
  static const u8    pay[] = {'x'};
  static rfcpin_wire w;
  sr_net             n;
  srvrun_conn*       c           = rfch3_fixture(&n);
  c->l.h3peer.ctrl.settings_seen = 0;
  sr_sl_send_headers(c, 0, "CONNECT", 0);
  CHECK(c->wt_active == 0);
  CHECK(wired_server_wt_open_uni(&c->wt, wired_span_of(pay, 1)) < 0);
  srvrun_sess_on_step(&g_sl_ctx, 0);
  rfch3_wire(&w, &n);
  CHECK(!rfch3_app_uni_sent(&w));
  sr_sl_send_settings(c);
  CHECK(c->wt_active == 1);
  CHECK(wired_server_wt_open_uni(&c->wt, wired_span_of(pay, 1)) >= 0);
  srvrun_sess_on_step(&g_sl_ctx, 0);
  rfcpin_wire_drain(&w, &g_sl_f, n.afd);
  CHECK(rfch3_app_uni_sent(&w));
  sr_net_close(&n);
}

/* RFC 9114 6.2.1 (9114-092): the server never closes its control stream.
 * Over a whole connection (rfch3_life: SETTINGS, a GET, GOAWAY, the
 * server's own CONNECTION_CLOSE) control stream 3 carries the 0x00 type,
 * SETTINGS first and the GOAWAY after it, and no STREAM frame on it has
 * FIN set; nor is it reset. */
static void test_srvrun_rfc9114_control_stream_never_fin(void) {
  static rfcpin_wire   w;
  const rfcpin_stream* s;
  u64                  t[8];
  usz                  k;
  rfch3_life(&w);
  s = rfcpin_wire_stream(&w, SRVRUN_CTRL_STREAM);
  CHECK(s != 0);
  if (!s) {
    return;
  }
  k = rfcpin_h3_types(s, 1, t, 8);
  CHECK(s->b[0] == H3_STREAM_CONTROL);
  CHECK(k == 2 && t[0] == H3_FRAME_SETTINGS && t[1] == H3_FRAME_GOAWAY);
  CHECK(s->fin == 0);
  CHECK(rfcpin_wire_reset_code(&w, SRVRUN_CTRL_STREAM) == ~0ULL);
  CHECK(w.kinds & (1u << FK_CONNECTION_CLOSE));
}

/* RFC 9114 7.2.4 (9114-061): SETTINGS identifiers the server does not
 * understand are ignored. The client's SETTINGS carries an unknown id
 * (0x1234), two reserved ones (0x21 and 0x1f * 7 + 0x21) and, between
 * them, SETTINGS_H3_DATAGRAM = 1: the connection stays up, the known
 * setting is read, and a WebTransport session is then established. */
static void test_srvrun_rfc9114_unknown_settings_ignored(void) {
  static const u64 sp[] = {
      0x1234, 7, 0x21, 0, H3_SETTING_H3_DATAGRAM, 1, 0x1f * 7 + 0x21, 99};
  sr_net       n;
  srvrun_conn* c = rfch3_fixture(&n);
  u8           ctrl[128];
  usz          len;
  c->l.h3peer.ctrl.settings_seen = 0;
  c->l.h3peer.h3_datagram        = 0;
  len = rfch3_ctrl(ctrl, sizeof ctrl, sp, 4, wired_span_of(0, 0));
  rfch3_send_stream(c, 2, 0, ctrl, len, 0);
  CHECK(!c->closing);
  CHECK(c->l.h3peer.ctrl.settings_seen == 1);
  CHECK(c->l.h3peer.h3_datagram == 1);
  sr_sl_send_headers(c, 0, "CONNECT", 0);
  CHECK(c->wt_active == 1);
  sr_net_close(&n);
}

/* RFC 9114 7.2.4.2 (9114-095): every setting whose value differs from its
 * default is in the server's SETTINGS. Read off the confirmation packet of
 * a full handshake offering WebTransport (rfcpin_confirm). The second pass
 * repeats it with 0-RTT acceptance staged (the sdrv flag set, no real
 * early data): SETTINGS construction does not take 0-RTT state as input
 * (control_settings.c), so this only shows the frame is unchanged; not
 * lowering remembered values on resumption is out of scope here. */
static void test_srvrun_rfc9114_nondefault_settings_sent(void) {
  static const u64 want[][2] = {
      {H3_SETTINGS_MAX_FIELD_SECTION_SIZE, WIRED_H3_MAX_FIELD_SECTION},
      {H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, DEFAULT_QPACK_MAX_TABLE_CAP},
      {H3_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1},
      {H3_SETTING_H3_DATAGRAM, 1},
      {H3_SETTINGS_WT_MAX_SESSIONS, 1},
      {H3_SETTINGS_WT_INITIAL_MAX_STREAMS_UNI,
       H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE},
      {H3_SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI,
       H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE},
      {H3_SETTINGS_WT_INITIAL_MAX_DATA, H3SETTINGS_WT_INIT_DATA_VALUE}};
  static rfcpin_wire w;
  for (int early = 0; early < 2; early++) {
    struct lp_fix        f;
    const rfcpin_stream* s;
    rfcpin_confirm(&f, &w, 1, early);
    CHECK(wired_server_early_data_used(&f.s) == early);
    s = rfcpin_wire_stream(&w, SRVRUN_CTRL_STREAM);
    CHECK(s != 0);
    for (usz i = 0; s && i < sizeof want / sizeof want[0]; i++) {
      u64 v = ~0ULL;
      CHECK(rfcpin_setting(s, want[i][0], &v) == 1);
      CHECK(v == want[i][1]);
    }
  }
}

/* What one peer error code leads to on the server path, for comparing a
 * code against H3_NO_ERROR (RFC 9114 8). */
typedef struct {
  int reset_freed;   /* RESET_STREAM ended the half-received request */
  int stop_answered; /* STOP_SENDING answered with RESET_STREAM (echoed) */
  int stop_freed;    /* ... and freed the answered response */
  int closing;       /* the server started closing on its own */
  int peer_closed;   /* CONNECTION_CLOSE put the connection to draining */
  int sent_after;    /* datagrams the server sent after that close */
} rfch3_outcome;

/* The three receive paths fed code: a RESET_STREAM on request stream 0
 * (HEADERS sent, no FIN), a STOP_SENDING on stream 4 (answered, response
 * not yet acknowledged), and an application CONNECTION_CLOSE. */
static rfch3_outcome rfch3_peer_code(u64 code) {
  static rfcpin_wire w;
  sr_net             n;
  srvrun_conn*       c = rfch3_fixture(&n);
  rfch3_outcome      o = {0};
  u8                 fr[64], pkt[PMTU_MAX];
  reset_stream_frame rs   = {0, code, 0};
  stop_sending_frame ss   = {4, code};
  conn_close_frame   cc   = {1, code, 0, 0, 0};
  usz                hlen = sr_sl_send_headers(c, 0, "GET", 0);
  rs.final_size           = hlen;
  sr_sl_step(c, fr, reset_stream_encode(fr, sizeof fr, &rs));
  o.reset_freed = !sr_sl_has_slot(c, 0);
  sr_sl_send_headers(c, 4, "GET", 1);
  CHECK(srvrun_resp_find(c, 4) != 0);
  sr_sl_step(c, fr, stop_sending_encode(fr, sizeof fr, &ss));
  o.stop_freed = srvrun_resp_find(c, 4) == 0;
  rfch3_wire(&w, &n);
  o.stop_answered = rfcpin_wire_reset_code(&w, 4) == code;
  o.closing       = c->closing;
  sr_sl_step(c, fr, frame_put_conn_close(fr, sizeof fr, &cc));
  o.peer_closed = c->l.peer_closed;
  srvrun_sess_on_step(&g_sl_ctx, 0);
  while (rfcpin_recv(n.afd, pkt)) {
    o.sent_after++;
  }
  sr_net_close(&n);
  return o;
}

static int rfch3_outcome_eq(rfch3_outcome a, rfch3_outcome b) {
  return a.reset_freed == b.reset_freed && a.stop_answered == b.stop_answered &&
         a.stop_freed == b.stop_freed && a.closing == b.closing &&
         a.peer_closed == b.peer_closed && a.sent_after == b.sent_after;
}

/* RFC 9114 8 / 8.1 (9114-075, 9114-076): an unknown error code, and a
 * reserved one (0x1f * N + 0x21), received on RESET_STREAM, STOP_SENDING
 * and CONNECTION_CLOSE are treated exactly as H3_NO_ERROR: each path ends
 * the same way it does for H3_NO_ERROR (rfch3_peer_code). */
static void test_srvrun_rfc9114_unknown_codes_as_no_error(void) {
  static const u64 codes[] = {0x12345678, 0x21, 0x1f * 1000 + 0x21};
  rfch3_outcome    base    = rfch3_peer_code(H3_NO_ERROR);
  CHECK(base.reset_freed && base.stop_answered && base.stop_freed);
  CHECK(!base.closing && base.peer_closed && base.sent_after == 0);
  for (usz i = 0; i < sizeof codes / sizeof codes[0]; i++) {
    CHECK(rfch3_outcome_eq(rfch3_peer_code(codes[i]), base));
  }
}

/* RFC 9114 4.6 / 7.2.7 (9114-032, 9114-070): the server never pushes and
 * never sends MAX_PUSH_ID -- even to a client that sent MAX_PUSH_ID. Over
 * the confirmation, the client's control stream with MAX_PUSH_ID 10, two
 * answered GETs, a GOAWAY and the server's close: every server uni stream
 * is the control (0x00) or a QPACK stream (0x02/0x03), none is a push
 * stream (0x01); the control stream carries no MAX_PUSH_ID; no response
 * stream carries PUSH_PROMISE. */
static void test_srvrun_rfc9114_no_push(void) {
  static const u64   none[] = {0};
  static rfcpin_wire w;
  sr_net             n;
  srvrun_conn*       c = rfch3_fixture(&n);
  u8                 mp[8], ctrl[64], out[256];
  usz                mpl = 0, len;
  u8                 id  = 10;
  wired_obuf         gob = obuf_of(out, sizeof out);
  u64                t[16];
  c->l.h3peer.ctrl.settings_seen = 0;
  rfch3_frame(mp, sizeof mp, &mpl, H3_FRAME_MAX_PUSH_ID, wired_span_of(&id, 1));
  len = rfch3_ctrl(ctrl, sizeof ctrl, none, 0, wired_span_of(mp, mpl));
  rfch3_send_stream(c, 2, 0, ctrl, len, 0);
  CHECK(!c->closing);
  sr_sl_send_headers(c, 0, "GET", 1);
  sr_sl_send_headers(c, 4, "GET", 1);
  CHECK(g_rfch3.calls == 2);
  CHECK(srvrun_send_goaway(&g_sl_cfg, c, &gob) == 1);
  srvrun_send_app_close(&g_sl_cfg, c, H3_NO_ERROR, wired_span_of(0, 0));
  rfch3_wire(&w, &n);
  CHECK(rfcpin_wire_stream(&w, 0) && rfcpin_wire_stream(&w, 4));
  for (usz i = 0; i < w.n; i++) {
    const rfcpin_stream* s = &w.s[i];
    usz                  k;
    if (s->id % 4 == 3) {
      CHECK(
          s->b[0] == H3_STREAM_CONTROL || s->b[0] == H3_STREAM_QPACK_ENCODER ||
          s->b[0] == H3_STREAM_QPACK_DECODER);
    }
    if (s->id % 4 != 0 && s->id != SRVRUN_CTRL_STREAM) {
      continue; /* QPACK streams carry instructions, not frames */
    }
    k = rfcpin_h3_types(s, s->id == SRVRUN_CTRL_STREAM, t, 16);
    CHECK(k != 0);
    for (usz j = 0; j < k; j++) {
      CHECK(t[j] != H3_FRAME_PUSH_PROMISE && t[j] != H3_FRAME_MAX_PUSH_ID);
    }
  }
  sr_net_close(&n);
}

void test_srvrun_rfc9114(void) {
  test_srvrun_rfc9110_trailers_not_in_headers();
  test_srvrun_rfc9114_rejected_only_unseen();
  test_srvrun_rfc9114_malformed_mid_body_message_error();
  test_srvrun_rfc9114_idle_no_keepalive();
  test_srvrun_rfc9114_no_server_bidi_outside_session();
  test_srvrun_rfc9114_no_wt_uni_before_peer_settings();
  test_srvrun_rfc9114_control_stream_never_fin();
  test_srvrun_rfc9114_unknown_settings_ignored();
  test_srvrun_rfc9114_nondefault_settings_sent();
  test_srvrun_rfc9114_unknown_codes_as_no_error();
  test_srvrun_rfc9114_no_push();
}
