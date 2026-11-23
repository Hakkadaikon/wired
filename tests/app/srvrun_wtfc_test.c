/* @file
 * Receive-side WebTransport session flow control of srvrun
 * (draft-ietf-webtrans-http3-16 5.1/5.3/5.4/5.6.2/5.6.4): the limits this
 * server advertises are enforced on the peer and raised by capsule as its
 * streams end and its data is consumed. Reuses srvrun_test.c's fixtures
 * (sr_wtsend_fixture, sr_wt_send_cfg, sr_kept_reset_code, sr_open_sockets,
 * sr_recv_stream, sr_sl_*), included earlier in the same unity TU.
 *
 * Test list:
 * - streams: a client bidi stream past the limit (24 by default, the
 *   whole table: the table refuses it) and a uni one past 6 close the
 *   session with
 *   WT_FLOW_CONTROL_ERROR; up to the limit it stays open; a stream the
 *   table refused while the client was inside its limit (server streams
 *   held the slots) is counted and owed back, the session stays; with two
 *   sessions it is charged to the one its signal names.
 * - data: Stream Body bytes past the WT_MAX_DATA in force close the session
 *   with WT_FLOW_CONTROL_ERROR; a reset stream's final size counts.
 * - raise: a client stream ending stages WT_MAX_STREAMS(limit + 1) on the
 *   CONNECT stream, once; consuming half a window stages WT_MAX_DATA
 *   (consumed + window); a stream rejected before its offer is owed too.
 * - long-lived: 300 sequential uni streams (each delivered and reaped) never
 *   trip the limit; the last capsule names 6 + 300.
 * - off: without flow control (5.1) nothing is counted or sent; a peer
 *   that declared only a data limit is not closed for streams but still
 *   gets WT_MAX_STREAMS raises.
 * - tick: a raise the CONNECT send slot refused goes out on the next tick
 *   with no further client packet.
 * - loss: a lost WT_MAX_STREAMS is sent again (RFC 9000 13.3).
 * (The same through real client packets: srvrun_wtfc_wire_test.c.) */

static void fc_on_data(
    void* ctx, wired_wt_session* s, u64 id, wired_span data, int fin) {
  (void)ctx;
  (void)s;
  (void)id;
  (void)data;
  (void)fin;
}

/* Session 0 (CONNECT stream 4) with flow control on both ways. */
static srvrun_conn* fc_fixture(struct lp_fix* f, wired_obuf* ob) {
  srvrun_conn* c          = sr_wtsend_fixture(f, ob);
  c->l.peer_wt_initial[0] = 1;
  c->l.peer_wt_initial[1] = 1;
  c->l.peer_wt_initial[2] = 1;
  c->wt.flow_control      = 1;
  c->wt.max_streams_bidi  = 1000;
  c->wt.max_streams_uni   = 1000;
  c->wt.max_data          = 1u << 30;
  srvrun_wtfc_open(c, 0);
  return c;
}

/* Claim a client WT stream slot whose signal names session 4: 0x41 (bidi)
 * or 0x54 (uni) as a 2-byte varint, then session id 4. */
static int fc_open(srvrun_conn* c, int bidi, u64 id) {
  static const u8 sig[2][3] = {{0x40, 0x54, 0x04}, {0x40, 0x41, 0x04}};
  int             i         = bidi ? wired_srvloop_wt_slot_claim(&c->l, id)
                                   : wired_srvloop_wt_uni_slot_claim(&c->l, id);
  CHECK(i >= 0);
  if (bidi) {
    bytes_memcpy(c->l.wt_streams[i].sig, sig[1], 3);
    c->l.wt_streams[i].sig_have = 3;
    c->l.wt_streams[i].sig_len  = 3;
  } else {
    bytes_memcpy(c->l.wt_uni_streams[i].sig, sig[0], 3);
    c->l.wt_uni_streams[i].sig_have = 3;
    c->l.wt_uni_streams[i].type_len = 3;
  }
  return i;
}

/* n client WT bidi streams for session 4 refused by a full table, as the
 * srvloop pass queues them (srvloop_wt_refuse_full). */
static void fc_refuse(srvrun_conn* c, usz n) {
  for (usz k = 0; k < n; k++) {
    c->l.wt_full.sid[c->l.wt_full.n++] = 4;
  }
}

static void fc_offer(const srvrun_cfg* cfg, srvrun_conn* c) {
  srvrun_offer_wt_streams(cfg, c);
  srvrun_offer_wt_uni_streams(cfg, c);
}

/* The last WT_MAX_STREAMS (kind 0 uni, 1 bidi) or WT_MAX_DATA (kind 2)
 * staged on CONNECT stream sid, 0 when none; *n counts them. */
static u64 fc_sent_on(srvrun_conn* c, u64 sid, int kind, usz* n) {
  const srvrun_wtsend* w   = srvrun_wtsend_find(c, sid);
  usz                  off = 0;
  u64                  v, last = 0;
  *n = 0;
  while (w && off < w->sess.q.len) {
    h3_frame   fr;
    usz        at = 0, k;
    wired_span p;
    k = h3_frame_get(
        wired_span_of(w->roundbuf + off, w->sess.q.len - off), &fr);
    CHECK(k != 0);
    if (k == 0) {
      break;
    }
    p = wired_span_of(fr.payload, fr.payload_len);
    if (kind == 2 ? wtcapsule_decode_max_data(p, &at, &v)
                  : wtcapsule_decode_max_streams(p, &at, kind, &v)) {
      last = v;
      (*n)++;
    }
    off += k;
  }
  return last;
}

static u64 fc_sent(srvrun_conn* c, int kind, usz* n) {
  return fc_sent_on(c, 4, kind, n);
}

/* The code the kept abort of stream id carries: its RESET_STREAM's, or --
 * a client uni stream has no send half to reset -- its STOP_SENDING's. */
static u64 fc_kept_code(const srvrun_conn* c, u64 id) {
  stop_sending_frame ss;
  if (sr_kept_reset_of(c, id)) {
    return sr_kept_reset_code(c, id);
  }
  for (usz i = 0; i < SRVRUN_RST_RETX; i++) {
    if (c->rst[i].pln &&
        stop_sending_decode(c->rst[i].pl, c->rst[i].pln, &ss) &&
        ss.stream_id == id) {
      return ss.error_code;
    }
  }
  return ~0ULL;
}

static void fc_check_closed(const srvrun_conn* c, u64 id) {
  CHECK(c->wt_active == 0);
  CHECK(fc_kept_code(c, id) == WTERR_FLOW_CONTROL_ERROR);
}

/* 5.6.2: "If an endpoint receives an incoming stream for a session that
 * would exceed the advertised Maximum Streams value, it MUST close the
 * WebTransport session with a WT_FLOW_CONTROL_ERROR". The bidi limit is
 * the whole table, so the stream past it is the one the table refuses. */
static void test_srvrun_wtfc_bidi_past_limit_closes(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  srvrun_conn*  c   = fc_fixture(&f, &ob);
  for (u64 k = 0; k < H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE; k++) {
    fc_open(c, 1, 8 + 4 * k);
  }
  fc_offer(&cfg, c);
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wt_active == 1);
  fc_refuse(c, 1);
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->l.wt_full.n == 0);
  fc_check_closed(c, 8);
}

/* A compliant client whose stream found the table full of server-opened
 * streams keeps its session; the refused stream is owed back. */
static void test_srvrun_wtfc_refused_within_limit_owed(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  srvrun_conn*  c   = fc_fixture(&f, &ob);
  usz           n;
  fc_refuse(c, 2);
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wt_active == 1);
  CHECK(c->wtx.fc[0].opened[1] == 2);
  CHECK(fc_sent(c, 1, &n) == H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE + 2);
}

/* With two sessions open, a refused stream is charged to the session its
 * signal names, not to the first one. */
static void test_srvrun_wtfc_refused_charged_to_named_session(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  srvrun_conn*  c   = fc_fixture(&f, &ob);
  wired_wt_session_init(&c->wt1, 8);
  wired_wt_session_establish(&c->wt1);
  c->wt1_active = 1;
  srvrun_wtfc_open(c, 1);
  c->l.wt_full.sid[c->l.wt_full.n++] = 8;
  c->l.wt_full.sid[c->l.wt_full.n++] = ~0ULL; /* signal split: no session */
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wtx.fc[0].opened[1] == 0);
  CHECK(c->wtx.fc[1].opened[1] == 1);
}

static void test_srvrun_wtfc_uni_past_limit_closes(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  srvrun_conn*  c   = fc_fixture(&f, &ob);
  u64           n   = H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE;
  for (u64 k = 0; k < n; k++) {
    fc_open(c, 0, 14 + 4 * k);
  }
  fc_offer(&cfg, c);
  CHECK(c->wt_active == 1);
  fc_open(c, 0, 14 + 4 * n);
  fc_offer(&cfg, c);
  fc_check_closed(c, 14 + 4 * n);
}

/* 5.6.4: "If an endpoint receives Stream Body data in excess of this
 * limit, it MUST close the WebTransport session with a
 * WT_FLOW_CONTROL_ERROR". At the limit it stays open. The stream's highest
 * offset (RFC 9000 4.5 accounting) counts, less its 3-byte signal. */
static void test_srvrun_wtfc_data_past_limit_closes(void) {
  struct lp_fix         f;
  u8                    obuf[1024];
  wired_obuf            ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg            cfg = sr_wt_send_cfg();
  srvrun_conn*          c   = fc_fixture(&f, &ob);
  wired_srvloop_rxacct* e;
  fc_open(c, 1, 8);
  fc_offer(&cfg, c);
  e = srvloop_rxacct_entry(&c->l, 8);
  CHECK(e != 0);
  e->fs.highest = H3SETTINGS_WT_INIT_DATA_VALUE + 3;
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wt_active == 1);
  e->fs.highest = H3SETTINGS_WT_INIT_DATA_VALUE + 4;
  srvrun_wtfc_step(&cfg, c);
  fc_check_closed(c, 8);
}

/* 5.4: a reset stream counts its final size (RFC 9000 4.5), less the
 * stream header -- here a 3-byte signal and a 1003-byte final size. */
static void test_srvrun_wtfc_reset_final_size_counts(void) {
  struct lp_fix         f;
  u8                    obuf[1024];
  wired_obuf            ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg            cfg = sr_wt_send_cfg();
  srvrun_conn*          c   = fc_fixture(&f, &ob);
  int                   i   = fc_open(c, 1, 8);
  wired_srvloop_rxacct* e   = srvloop_rxacct_entry(&c->l, 8);
  fc_offer(&cfg, c);
  CHECK(e != 0 && finalsize_set(&e->fs, 1003));
  srvrun_wt_bidi_slot_free(c, &c->l.wt_streams[i]);
  CHECK(c->wtx.fc[0].done == 1000);
  c->wtx.fc[0].max_data = 999;
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wt_active == 0);
}

/* 5.6: "Endpoints SHOULD send WT_MAX_DATA and WT_MAX_STREAMS capsules as
 * they consume data or close streams" -- one per ended stream, once. */
static void test_srvrun_wtfc_stream_end_raises_limit(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  srvrun_conn*  c   = fc_fixture(&f, &ob);
  int           b   = fc_open(c, 1, 8);
  int           u   = fc_open(c, 0, 14);
  usz           n;
  fc_offer(&cfg, c);
  srvrun_wtfc_step(&cfg, c);
  CHECK(fc_sent(c, 1, &n) == 0 && n == 0);
  srvrun_wt_bidi_slot_free(c, &c->l.wt_streams[b]);
  srvrun_wt_uni_slot_free(c, &c->l.wt_uni_streams[u]);
  srvrun_wtfc_step(&cfg, c);
  CHECK(fc_sent(c, 1, &n) == H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE + 1);
  CHECK(n == 1);
  CHECK(fc_sent(c, 0, &n) == H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE + 1);
  CHECK(n == 1);
  srvrun_wtfc_step(&cfg, c);
  fc_sent(c, 1, &n);
  CHECK(n == 1); /* nothing more until another stream ends */
}

/* A client stream the session rejected before its offer (buffer full) was
 * still opened against the limit: it is owed back like an ended one. */
static void test_srvrun_wtfc_rejected_stream_owed(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  srvrun_conn*  c   = fc_fixture(&f, &ob);
  usz           n;
  c->wt.state = WIRED_WT_UNESTABLISHED; /* buffers, then rejects */
  for (u64 k = 0; k <= WIRED_WT_MAX_BUFFERED_STREAMS; k++) {
    fc_open(c, 0, 14 + 4 * k);
  }
  fc_offer(&cfg, c);
  c->wt.state = WIRED_WT_ESTABLISHED;
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wtx.fc[0].opened[0] == WIRED_WT_MAX_BUFFERED_STREAMS + 1);
  CHECK(fc_sent(c, 0, &n) == H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE + 1);
}

static void test_srvrun_wtfc_consumed_data_raises_limit(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  srvrun_conn*  c   = fc_fixture(&f, &ob);
  u64           w   = H3SETTINGS_WT_INIT_DATA_VALUE;
  int           i   = fc_open(c, 1, 8);
  usz           n;
  fc_offer(&cfg, c);
  c->l.wt_streams[i].delivered_len = w / 2 - 1;
  srvrun_wtfc_step(&cfg, c);
  CHECK(fc_sent(c, 2, &n) == 0 && n == 0); /* under half a window */
  c->l.wt_streams[i].delivered_len = w / 2;
  srvrun_wtfc_step(&cfg, c);
  CHECK(fc_sent(c, 2, &n) == w / 2 + w && n == 1);
  CHECK(c->wtx.fc[0].max_data == w / 2 + w);
}

/* A long-lived MoQT-style session: one uni stream per message, 300 of them
 * one after another, each delivered (FIN) and reaped -- far past the
 * initial limit of 6, never a flow-control error. */
static void test_srvrun_wtfc_long_lived_session(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  srvrun_conn*  c   = fc_fixture(&f, &ob);
  usz           n;
  cfg.wt_on_stream_data = fc_on_data;
  for (u64 k = 0; k < 300; k++) {
    int i                          = fc_open(c, 0, 14 + 4 * k);
    c->l.wt_uni_streams[i].fin     = 1;
    c->l.wt_uni_streams[i].fin_off = 0;
    fc_offer(&cfg, c);
    CHECK(!c->l.wt_uni_streams[i].in_use); /* reaped */
    srvrun_wtfc_step(&cfg, c);
  }
  CHECK(c->wt_active == 1);
  CHECK(fc_sent(c, 0, &n) == H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE + 300);
  CHECK(n == 300);
}

/* 5.1: no flow control without the peer's SETTINGS_WT_INITIAL_* -- nothing
 * counted or enforced, no capsule sent. */
static void test_srvrun_wtfc_off_without_peer_settings(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  srvrun_conn*  c   = sr_wtsend_fixture(&f, &ob);
  int           i   = 0;
  srvrun_wtfc_open(c, 0);
  for (u64 k = 0; k < 20; k++) {
    i = fc_open(c, 1, 8 + 4 * k);
  }
  fc_offer(&cfg, c);
  fc_refuse(c, 5);
  srvrun_wt_bidi_slot_free(c, &c->l.wt_streams[i]);
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wt_active == 1);
  CHECK(c->wtx.fc[0].opened[1] == 0);
  CHECK(srvrun_wtsend_find(c, 4) == 0);
}

/* 5.1: a peer that declared only SETTINGS_WT_INITIAL_MAX_DATA (proxygen)
 * still has flow control on: an ended stream draws WT_MAX_STREAMS, so one
 * that honours our limit never stalls; it is not closed for streams
 * (interop: it does not count them), but its data limit holds. */
static void test_srvrun_wtfc_data_only_peer(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg    cfg = sr_wt_send_cfg();
  srvrun_conn*  c   = fc_fixture(&f, &ob);
  usz           n;
  int           i         = 0;
  c->l.peer_wt_initial[0] = 0;
  c->l.peer_wt_initial[1] = 0;
  srvrun_wtfc_open(c, 0);
  for (u64 k = 0; k < WIRED_SRVLOOP_MAX_WT_STREAMS; k++) {
    i = fc_open(c, 1, 8 + 4 * k);
  }
  fc_offer(&cfg, c);
  fc_refuse(c, 3); /* past the limit: not closed */
  srvrun_wt_bidi_slot_free(c, &c->l.wt_streams[i]);
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wt_active == 1);
  CHECK(fc_sent(c, 1, &n) == H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE + 4);
  c->wtx.fc[0].max_data     = 1;
  c->l.wt_streams[0].win.hi = 2;
  srvrun_wtfc_step(&cfg, c);
  CHECK(c->wt_active == 0);
}

/* A raise the CONNECT stream's send slot could not take (every send slot
 * busy) goes out on the next tick, with no further packet from the client
 * -- which may be waiting for exactly that credit. */
static void test_srvrun_wtfc_refused_raise_sent_on_tick(void) {
  struct lp_fix   f;
  u8              obuf[1024];
  wired_obuf      ob  = obuf_of(obuf, sizeof obuf);
  srvrun_cfg      cfg = sr_wt_send_cfg();
  srvrun_conn*    c   = fc_fixture(&f, &ob);
  srvrun_state    st  = {g_srvrun_table, g_srvrun_state.conns};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 0, 0};
  int             i   = fc_open(c, 1, 8);
  usz             n;
  fc_offer(&cfg, c);
  for (usz k = 0; k < SRVRUN_WT_SEND_SLOTS; k++) {
    c->wtsend[k].in_use    = 1;
    c->wtsend[k].stream_id = 1001 + 4 * k;
  }
  c->wtx.send_free = 0;
  srvrun_wt_bidi_slot_free(c, &c->l.wt_streams[i]);
  srvrun_wtfc_step(&cfg, c);
  CHECK(srvrun_wtsend_find(c, 4) == 0); /* refused: still owed */
  CHECK(c->wtx.fc[0].owed[1] == 1);
  for (usz k = 0; k < SRVRUN_WT_SEND_SLOTS; k++) {
    c->wtsend[k].in_use = 0;
  }
  c->up = 1;
  srvrun_wt_app_pending_slot(&ctx, 0);
  CHECK(fc_sent(c, 1, &n) == H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE + 1);
}

/* RFC 9000 13.3: the raise is CONNECT-stream data, so a lost packet
 * carrying it is sent again after the probe timeout. */
static void test_srvrun_wtfc_raise_retransmitted_after_loss(void) {
  struct lp_fix f;
  u8            obuf[1024];
  wired_obuf    ob = obuf_of(obuf, sizeof obuf);
  sockaddr      srv;
  i64           sfd, cfd;
  stream_frame  sf;
  srvrun_conn*  c;
  usz           at = 0;
  u64           v  = 0;
  h3_frame      fr;
  if (!sr_open_sockets(&sfd, &cfd, &srv)) {
    return; /* sandbox: skip */
  }
  poll_set_nonblock(sfd);
  c       = fc_fixture(&f, &ob);
  c->peer = srv;
  {
    srvrun_cfg cfg = {
        cfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env, 0, 0, 0,
        0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    srvrun_state    st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_step_ctx ctx = {&cfg, &srv, &st, 0, 0};
    int             i   = fc_open(c, 1, 8);
    fc_offer(&cfg, c);
    srvrun_wt_bidi_slot_free(c, &c->l.wt_streams[i]);
    srvrun_wtfc_step(&cfg, c);
    srvrun_pump_sess(&ctx, 0);
    CHECK(sr_recv_stream(&f, sfd, 4, &sf)); /* sent once -- and lost */
    srvrun_pto_requeue_all(c);
    c->srtt_ms      = 0;
    c->next_send_ms = 0;
    srvrun_pump_sess(&ctx, 0);
  }
  CHECK(sr_recv_stream(&f, sfd, 4, &sf)); /* retransmitted */
  CHECK(sf.offset == 0 && h3_frame_get(wired_span_of(sf.data, sf.length), &fr));
  CHECK(wtcapsule_decode_max_streams(
      wired_span_of(fr.payload, fr.payload_len), &at, 1, &v));
  CHECK(v == H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE + 1);
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

void test_srvrun_wtfc(void) {
  test_srvrun_wtfc_bidi_past_limit_closes();
  test_srvrun_wtfc_refused_within_limit_owed();
  test_srvrun_wtfc_refused_charged_to_named_session();
  test_srvrun_wtfc_uni_past_limit_closes();
  test_srvrun_wtfc_data_past_limit_closes();
  test_srvrun_wtfc_reset_final_size_counts();
  test_srvrun_wtfc_stream_end_raises_limit();
  test_srvrun_wtfc_rejected_stream_owed();
  test_srvrun_wtfc_consumed_data_raises_limit();
  test_srvrun_wtfc_long_lived_session();
  test_srvrun_wtfc_off_without_peer_settings();
  test_srvrun_wtfc_data_only_peer();
  test_srvrun_wtfc_refused_raise_sent_on_tick();
  test_srvrun_wtfc_raise_retransmitted_after_loss();
}
