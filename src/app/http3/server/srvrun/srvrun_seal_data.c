#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_seal_data_blocked(srvrun_conn* c, u64 limit, wired_obuf* out);
static int srvrun_seal_streams_blocked(
    srvrun_conn* c, int uni, u64 limit, wired_obuf* out);

/* Seal one DATA_BLOCKED frame (RFC 9000 19.12) as its own 1-RTT packet and
 * send it, mirroring srvrun_seal_max_data for the connection-wide limit. */
static int srvrun_seal_data_blocked(
    srvrun_conn* c, u64 limit, wired_obuf* out) {
  u8                    pl[24];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  data_frame            f   = {limit};
  wired_srvloop_send_in sin;
  usz                   pln = data_blocked_encode(plb.p, plb.cap, &f);
  if (!pln) {
    return 0;
  }
  plb.len = pln;
  sin     = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      c->l.tx_pn++,
      -1,
      wired_span_of(pl, pln),
      0,
      0,
      0,
      0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* RFC 9000 4.1/19.12: "A sender SHOULD send a DATA_BLOCKED... This can be
 * useful for debugging purposes... at the connection level" -- letting the
 * peer know the SERVER (not just the client) is flow-control-blocked so it
 * knows to raise MAX_DATA sooner than its own autotuning would otherwise.
 * limit is c->conn_credit itself (the ceiling that blocked this send). */
void srvrun_send_data_blocked(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 limit) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_data_blocked(c, limit, &ob)) {
    return;
  }
  /* Once per blocking ceiling, so cheap enough to log unconditionally: a
   * peer whose MAX_DATA never rises again silently stalls every later
   * stream on the connection. */
  wired_log_str("conn send blocked: peer MAX_DATA exhausted\n");
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "DATA_BLOCKED sent\n");
}

/* RFC 9000 19.13: STREAM_DATA_BLOCKED naming stream_id's credit, sealed as
 * its own 1-RTT packet and sent. */
void srvrun_send_stream_data_blocked(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id, u64 limit) {
  u8                pl[24], out[128];
  wired_obuf        ob = obuf_of(out, sizeof out);
  stream_data_frame f  = {stream_id, limit};
  usz               n  = stream_data_blocked_encode(pl, sizeof pl, &f);
  if (!srvrun_seal_ctl(c, pl, n, &ob)) {
    return;
  }
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "STREAM_DATA_BLOCKED sent\n");
}

/* Seal one MAX_STREAMS frame (RFC 9000 19.11, uni selects 0x13) as its own
 * 1-RTT packet and send it. */
int srvrun_seal_max_streams(
    srvrun_conn* c, int uni, u64 value, wired_obuf* out) {
  u8                    pl[24];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  if (!maxstreams_frame(uni, value, &plb)) {
    return 0;
  }
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      c->l.tx_pn++,
      -1,
      wired_span_of(pl, plb.len),
      0,
      0,
      0,
      0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Seal one STREAMS_BLOCKED frame (RFC 9000 19.14, uni selects 0x17) as its
 * own 1-RTT packet and send it -- srvrun_seal_max_streams' mirror for the
 * SENDER-blocked signal instead of the receiver-side grant. */
static int srvrun_seal_streams_blocked(
    srvrun_conn* c, int uni, u64 limit, wired_obuf* out) {
  u8                    pl[24];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  if (!maxstreams_blocked_frame(uni, limit, &plb)) {
    return 0;
  }
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      c->l.tx_pn++,
      -1,
      wired_span_of(pl, plb.len),
      0,
      0,
      0,
      0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* RFC 9000 4.6 19.14: "A sender SHOULD send a STREAMS_BLOCKED frame... This
 * can be useful for debugging purposes" -- tells the peer this SERVER ran
 * out of its own uni-stream grant for server-initiated (relay) opens, once
 * per distinct ceiling (srvrun_notify_uni_blocked's own doc). limit is the
 * peer_uni_stream_limit that refused the open. */
void srvrun_send_streams_blocked(
    const srvrun_cfg* cfg, srvrun_conn* c, int uni, u64 limit) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_streams_blocked(c, uni, limit, &ob)) {
    return;
  }
  c->stat_streams_blocked++;
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "UNI STREAMS_BLOCKED sent\n");
}
