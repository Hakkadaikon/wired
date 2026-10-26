/* @file
 * WebTransport session establishment and session errors on srvrun's shipping
 * path (draft-ietf-webtrans-http3-16 3.1/3.2/4/5.4/6, RFC 9297 2.1.1/3.2).
 * Every case seals real client packets through sr_sl_step (srvrun_test.c),
 * included earlier in the same unity TU, as do srvrun_close_test.c's
 * src_connect_send / src_kept_close / src_connect_fin_sent.
 *
 * Test list:
 * - malformed CONNECT (RFC 9114 4.1.2, reset H3_MESSAGE_ERROR, no session,
 *   no response): :scheme http (3.2); Content-Length, Content-Type or
 *   Transfer-Encoding on the capsule-protocol request (RFC 9297 3.2); any
 *   other regular field still establishes.
 * - client requirements (3.1): a held CONNECT is rejected as malformed when
 *   the client's SETTINGS carry SETTINGS_H3_DATAGRAM=0 or omit it, and
 *   established when they carry 1; a value of 2 closes the connection with
 *   H3_SETTINGS_ERROR (RFC 9297 2.1.1); a webtransport-h3 CONNECT needs the
 *   client's reset_stream_at TP, the draft-07 "webtransport" token does not.
 * - DATAGRAM send (RFC 9297 2.1.1): refused until the peer's
 *   SETTINGS_H3_DATAGRAM=1 has been received.
 * - session id (4): a WT uni or bidi stream naming a non-client-bidi session
 *   id closes the connection with H3_ID_ERROR; one naming a client-bidi id
 *   with no live session (a closed one, 4/WTH3-031) does not.
 * - WT_MAX_STREAM_DATA / WT_STREAM_DATA_BLOCKED (5.4): close the session. */

#define WTS_NONE (~(u64)0)

/* The error code of the kept RESET_STREAM on stream id, WTS_NONE if none. */
static u64 wts_reset_code(const srvrun_conn* c, u64 id) {
  for (usz i = 0; i < SRVRUN_RST_RETX; i++) {
    const srvrun_rst*  e  = &c->rst[i];
    reset_stream_frame rs = {0, 0, 0};
    if (e->pln && e->pl[0] == 0x04 && reset_stream_decode(e->pl, e->pln, &rs) &&
        rs.stream_id == id) {
      return rs.error_code;
    }
  }
  return WTS_NONE;
}

static wired_span wts_s(const char* s) {
  return wired_span_of((const u8*)s, wired_cstr_len(s));
}

/* A CONNECT on stream id (:scheme scheme, :protocol proto) plus one regular
 * field line hname: hval when hname is non-null, as one client packet with
 * no FIN. Returns the HEADERS frame's length. */
static usz wts_connect(
    srvrun_conn* c,
    u64          id,
    const char*  scheme,
    const char*  proto,
    const char*  hname,
    const char*  hval) {
  u8              fields[256], h3buf[300], pl[512];
  wired_obuf      fob = obuf_of(fields, sizeof fields);
  wired_obuf      hob = obuf_of(h3buf, sizeof h3buf);
  wired_obuf      sob = obuf_of(pl, sizeof pl);
  h3req_pseudo_in pin = {
      wts_s("CONNECT"), wts_s(scheme), wts_s("h"), wts_s("/"), wts_s(proto)};
  CHECK(h3req_enc_pseudo(&pin, &fob) == 1);
  if (hname) { /* h3req_enc_header writes from its buffer's start */
    wired_obuf lob = obuf_of(fields + fob.len, sizeof fields - fob.len);
    CHECK(h3req_enc_header(wts_s(hname), wts_s(hval), &lob) == 1);
    fob.len += lob.len;
  }
  CHECK(h3_frame_put(&hob, H3_FRAME_HEADERS, wired_span_of(fields, fob.len)));
  {
    stream_frame sf = {id, 0, hob.len, h3buf, 0};
    CHECK(appdata_stream_frame(&sf, &sob) == 1);
  }
  sr_sl_step(c, pl, sob.len);
  return hob.len;
}

/* The CONNECT on stream 0 was refused as malformed: no session, no
 * response, its stream reset with H3_MESSAGE_ERROR. */
static void wts_check_malformed(const srvrun_conn* c) {
  CHECK(c->wt_active == 0);
  CHECK(c->resp[0].in_use == 0);
  CHECK(wts_reset_code(c, 0) == H3_MESSAGE_ERROR);
  CHECK(g_sr_wt_handler_calls == 0);
}

static void test_srvrun_wt_connect_http_scheme_malformed(void) {
  srvrun_conn* c = sr_sl_fixture();
  wts_connect(c, 0, "http", "webtransport", 0, 0);
  wts_check_malformed(c);
}

static void test_srvrun_wt_connect_capsule_forbidden_fields_malformed(void) {
  static const char* const bad[][2] = {
      {"content-length", "0"},
      {"content-type", "text/plain"},
      {"transfer-encoding", "chunked"}};
  for (usz i = 0; i < 3; i++) {
    srvrun_conn* c = sr_sl_fixture();
    wts_connect(c, 0, "https", "webtransport", bad[i][0], bad[i][1]);
    wts_check_malformed(c);
  }
}

static void test_srvrun_wt_connect_other_field_establishes(void) {
  srvrun_conn* c = sr_sl_fixture();
  wts_connect(c, 0, "https", "webtransport", "x-a", "b");
  CHECK(c->wt_active == 1);
  CHECK(wts_reset_code(c, 0) == WTS_NONE);
}

/* The client's control stream (2) carrying SETTINGS: one
 * SETTINGS_H3_DATAGRAM=v pair, or none when v is WTS_NONE. */
static void wts_send_settings(srvrun_conn* c, u64 v) {
  u8           ctrl[16], pl[64];
  usz          n   = 0;
  wired_obuf   sob = obuf_of(pl, sizeof pl);
  stream_frame sf;
  ctrl[n++] = 0x00; /* control stream type */
  ctrl[n++] = H3_FRAME_SETTINGS;
  ctrl[n++] = v == WTS_NONE ? 0 : 2;
  if (v != WTS_NONE) {
    ctrl[n++] = H3_SETTING_H3_DATAGRAM;
    ctrl[n++] = (u8)v;
  }
  sf = (stream_frame){2, 0, n, ctrl, 0};
  CHECK(appdata_stream_frame(&sf, &sob) == 1);
  sr_sl_step(c, pl, sob.len);
}

/* A CONNECT held for the client's SETTINGS, which then arrive with
 * SETTINGS_H3_DATAGRAM v (the production default before SETTINGS: 0). */
static srvrun_conn* wts_held_then_settings(u64 v) {
  srvrun_conn* c          = sr_sl_fixture_no_settings();
  c->l.h3peer.h3_datagram = 0;
  wts_connect(c, 0, "https", "webtransport", 0, 0);
  CHECK(c->wt_held_mask != 0);
  wts_send_settings(c, v);
  CHECK(c->wt_held_mask == 0);
  return c;
}

static void test_srvrun_wt_settings_h3_datagram_required(void) {
  srvrun_conn* c = wts_held_then_settings(0);
  wts_check_malformed(c);
  CHECK(c->closing == 0);
  c = wts_held_then_settings(WTS_NONE);
  wts_check_malformed(c);
  c = wts_held_then_settings(1);
  CHECK(c->wt_active == 1);
  CHECK(c->l.h3peer.h3_datagram == 1);
}

static void test_srvrun_settings_h3_datagram_two_closes_connection(void) {
  srvrun_conn* c = sr_sl_fixture_no_settings();
  wts_send_settings(c, 2);
  CHECK(c->closing == 1);
  CHECK(src_kept_close(c).error_code == H3_SETTINGS_ERROR);
}

/* WTH3-007: no max_datagram_frame_size TP is malformed too. */
static void test_srvrun_wt_no_datagram_tp_malformed(void) {
  srvrun_conn* c                         = sr_sl_fixture();
  c->s.sdrv.peer_max_datagram_frame_size = 0;
  wts_connect(c, 0, "https", "webtransport", 0, 0);
  wts_check_malformed(c);
}

static void test_srvrun_wt_h3_token_requires_reset_stream_at(void) {
  srvrun_conn* c                 = sr_sl_fixture();
  c->s.sdrv.peer_reset_stream_at = 0;
  wts_connect(c, 0, "https", "webtransport-h3", 0, 0);
  wts_check_malformed(c);
  c                              = sr_sl_fixture();
  c->s.sdrv.peer_reset_stream_at = 1;
  wts_connect(c, 0, "https", "webtransport-h3", 0, 0);
  CHECK(c->wt_active == 1);
  c                              = sr_sl_fixture();
  c->s.sdrv.peer_reset_stream_at = 0; /* draft-07 token: not required */
  wts_connect(c, 0, "https", "webtransport", 0, 0);
  CHECK(c->wt_active == 1);
}

static void test_srvrun_wt_datagram_needs_peer_h3_datagram(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob        = obuf_of(obuf, sizeof obuf);
  srvrun_conn*  c         = sr_wtsend_fixture(&f, &ob);
  wired_span    d         = wired_span_of(sr_dg_payload, sizeof sr_dg_payload);
  usz           n0        = g_srvrun_env.dgring_n;
  c->l.h3peer.h3_datagram = 0;
  CHECK(wired_server_wt_send_datagram_to(&c->wt, d) == 0);
  CHECK(srvrun_queue_datagram(c, d) == 0);
  CHECK(g_srvrun_env.dgring_n == n0);
  c->l.h3peer.h3_datagram = 1;
  CHECK(srvrun_queue_datagram(c, d) == 1);
}

/* One STREAM frame on stream id carrying d at offset 0, no FIN. */
static void wts_stream(srvrun_conn* c, u64 id, const u8* d, usz n) {
  u8           pl[64];
  wired_obuf   sob = obuf_of(pl, sizeof pl);
  stream_frame sf  = {id, 0, n, d, 0};
  CHECK(appdata_stream_frame(&sf, &sob) == 1);
  sr_sl_step(c, pl, sob.len);
}

/* An established session on CONNECT stream 0, then stream id opening with
 * the 2-byte signal varint sig naming session sid. */
static srvrun_conn* wts_signal(u64 id, u8 sig, u8 sid) {
  srvrun_conn* c   = sr_sl_fixture();
  u8           d[] = {0x40, sig, sid, 'x'};
  wts_connect(c, 0, "https", "webtransport", 0, 0);
  CHECK(c->wt_active == 1);
  wts_stream(c, id, d, sizeof d);
  return c;
}

static void test_srvrun_wt_non_client_bidi_session_id_closes(void) {
  static const struct {
    u64 id;
    u8  sig, sid;
  } rows[] = {{14, 0x54, 1}, {14, 0x54, 2}, {4, 0x41, 3}, {4, 0x41, 6}};
  for (usz i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    srvrun_conn* c = wts_signal(rows[i].id, rows[i].sig, rows[i].sid);
    CHECK(c->closing == 1);
    CHECK(src_kept_close(c).error_code == H3_ID_ERROR);
  }
}

/* 4 / WTH3-031: a client-bidi id with no live session is not invalid. */
static void test_srvrun_wt_closed_session_id_not_an_id_error(void) {
  srvrun_conn* c = wts_signal(14, 0x54, 8);
  CHECK(c->closing == 0);
  c = wts_signal(4, 0x41, 8);
  CHECK(c->closing == 0);
  CHECK(c->wt_active == 1);
}

/* DATA-framed capsule (type, one-varint value 5) on CONNECT stream 0 at
 * offset at. */
static void wts_capsule(srvrun_conn* c, u64 at, u64 type) {
  u8         cap[32];
  u8         v[] = {5};
  wired_obuf b   = obuf_of(cap, sizeof cap);
  CHECK(capsule_encode(&b, type, wired_span_of(v, 1)) == 1);
  sr_h3data(&b, 0);
  src_connect_send(c, at, cap, b.len, 0);
}

static void test_srvrun_wt_stream_level_flow_capsule_session_error(void) {
  static const u64 types[] = {
      WTCAPSULE_TYPE_MAX_STREAM_DATA, WTCAPSULE_TYPE_STREAM_DATA_BLOCKED};
  for (usz i = 0; i < 2; i++) {
    srvrun_conn* c    = sr_sl_fixture();
    usz          hlen = wts_connect(c, 0, "https", "webtransport", 0, 0);
    wts_capsule(c, hlen, types[i]);
    CHECK(g_sl_closes == 1);
    CHECK(c->wt_active == 0);
    CHECK(src_connect_fin_sent(c));
    CHECK(c->closing == 0);
  }
}

void test_srvrun_wtsess(void) {
  test_srvrun_wt_connect_http_scheme_malformed();
  test_srvrun_wt_connect_capsule_forbidden_fields_malformed();
  test_srvrun_wt_connect_other_field_establishes();
  test_srvrun_wt_settings_h3_datagram_required();
  test_srvrun_settings_h3_datagram_two_closes_connection();
  test_srvrun_wt_no_datagram_tp_malformed();
  test_srvrun_wt_h3_token_requires_reset_stream_at();
  test_srvrun_wt_datagram_needs_peer_h3_datagram();
  test_srvrun_wt_non_client_bidi_session_id_closes();
  test_srvrun_wt_closed_session_id_not_an_id_error();
  test_srvrun_wt_stream_level_flow_capsule_session_error();
}
