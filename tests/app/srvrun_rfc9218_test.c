#include "test.h"

/* RFC 9218 rows pinned on the server's shipping path: concurrent requests
 * sealed for real and stepped through the sr_sl_* fixture (srvrun_test.c),
 * the streaming responses read back off a loopback socket (rfch3_*,
 * srvrun_test.c) round by round as the client acknowledges. */

/* Append one STREAM frame on id carrying a HEADERS frame for fs[0..fn) to
 * pl[*len..cap). */
static void p9218_req(
    u8* pl, usz cap, usz* len, u64 id, wired_span fs, int fin) {
  u8           h3[256];
  usz          hl  = 0;
  wired_obuf   sob = obuf_of(pl + *len, cap - *len);
  stream_frame sf;
  rfch3_frame(h3, sizeof h3, &hl, H3_FRAME_HEADERS, fs);
  sf = (stream_frame){id, 0, hl, h3, (u8)fin};
  CHECK(appdata_stream_frame(&sf, &sob) == 1);
  *len += sob.len;
}

/* A GET with a priority header of value pv (RFC 9218 5) on id. */
static void p9218_get(u8* pl, usz cap, usz* len, u64 id, const char* pv) {
  const char* const nv[] = {"priority", pv};
  u8                fs[128];
  wired_obuf        fob = obuf_of(fs, sizeof fs);
  rfch3_fields(&fob, "GET", nv, 1);
  p9218_req(pl, cap, len, id, wired_span_of(fs, fob.len), 1);
}

/* Stream bytes the server has sent on id so far (its largest offset). */
static usz p9218_sent(rfcpin_wire* w, u64 id) {
  const rfcpin_stream* s = rfcpin_wire_stream(w, id);
  return s ? s->end : 0;
}

/* Run rounds rounds of: read what the server sent, check every stream in
 * ids[0..n) advanced since the last round and none is more than two
 * chunks ahead of another, then acknowledge every packet from pn lo on
 * (the step that processes the ACK pumps the next round). */
static void p9218_rounds(
    srvrun_conn* c, const sr_net* net, const u64* ids, usz n, u64 lo) {
  static rfcpin_wire w;
  usz                last[4] = {0};
  int                rounds  = 4;
  bytes_memset(&w, 0, sizeof w);
  for (int r = 0; r < rounds; r++) {
    usz lo_b = ~(usz)0, hi_b = 0;
    rfcpin_wire_drain(&w, &g_sl_f, net->afd);
    for (usz i = 0; i < n; i++) {
      usz b = p9218_sent(&w, ids[i]);
      CHECK(b > last[i]);
      last[i] = b;
      lo_b    = b < lo_b ? b : lo_b;
      hi_b    = b > hi_b ? b : hi_b;
    }
    CHECK(hi_b - lo_b <= 2 * SRVRUN_CHUNK);
    sr_sl_ack_from(c, lo);
  }
}

/* The fixture answering every request with a streaming body far longer
 * than one congestion window (sr_stream_body_handler), cwnd held to six
 * chunks so each pass has to share. */
static srvrun_conn* p9218_fixture(sr_net* n) {
  srvrun_conn* c      = rfch3_fixture(n);
  g_sl_cfg.handler    = sr_stream_body_handler;
  sr_stream_total_len = 64 * SRVRUN_CHUNK;
  sr_stream_round_cap = 8 * SRVRUN_CHUNK;
  c->cc.cwnd          = SR_WIN(6);
  return c;
}

/* RFC 9218 10 (9218-018, 9218-020): responses of one urgency share the
 * bandwidth, and a non-incremental one among incremental ones is not
 * starved. Three GETs arrive in one packet: 0 and 4 are `u=3, i`, 8 is
 * `u=3` (non-incremental). Over four acknowledged rounds every response
 * advances each round, none more than two chunks ahead of another. */
static void test_srvrun_rfc9218_same_urgency_shares(void) {
  static const u64 ids[] = {0, 4, 8};
  sr_net           n;
  srvrun_conn*     c = p9218_fixture(&n);
  u8               pl[1200];
  usz              len = 0;
  u64              lo;
  p9218_get(pl, sizeof pl, &len, 0, "u=3, i");
  p9218_get(pl, sizeof pl, &len, 4, "u=3, i");
  p9218_get(pl, sizeof pl, &len, 8, "u=3");
  lo = c->l.tx_pn;
  sr_sl_step(c, pl, len);
  for (usz i = 0; i < 3; i++) {
    const wired_srvloop_stream_slot* s = srvrun_req_slot_of(c, ids[i]);
    CHECK(s && s->priority.urgency == 3 && s->priority.incremental == (i < 2));
  }
  p9218_rounds(c, &n, ids, 3, lo);
  sr_net_close(&n);
}

/* RFC 9218 10.1 / 11 (9218-021): a CONNECT tunnel stream (RFC 9114 4.4:
 * :method and :authority only, the stream left open) is scheduled with
 * the other streams: a tunnel on 0 and a GET on 4, both answered with
 * long bodies, both advance in every acknowledged round. */
static void test_srvrun_rfc9218_connect_tunnel_shares(void) {
  static const u64 ids[] = {0, 4};
  sr_net           n;
  srvrun_conn*     c = p9218_fixture(&n);
  u8               fs[64], pl[1200];
  wired_obuf       fob = obuf_of(fs, sizeof fs);
  usz              len = 0;
  u64              lo;
  CHECK(
      h3req_enc_connect(wired_span_of((const u8*)"localhost:443", 13), &fob) ==
      1);
  p9218_req(pl, sizeof pl, &len, 0, wired_span_of(fs, fob.len), 0);
  p9218_get(pl, sizeof pl, &len, 4, "u=3");
  lo = c->l.tx_pn;
  sr_sl_step(c, pl, len);
  CHECK(srvrun_resp_find(c, 0) != 0 && srvrun_resp_find(c, 4) != 0);
  p9218_rounds(c, &n, ids, 2, lo);
  sr_net_close(&n);
}

void test_srvrun_rfc9218(void) {
  test_srvrun_rfc9218_same_urgency_shares();
  test_srvrun_rfc9218_connect_tunnel_shares();
}
