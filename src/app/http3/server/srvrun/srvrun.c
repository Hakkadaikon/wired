#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_rx_hs_adv(const srvrun_rxmark* m, const wired_srvloop* l);
static int srvrun_rx_advanced(const srvrun_rxmark* m, const wired_srvloop* l);
static u64 srvrun_rx_pn(const srvrun_rxmark* m, const wired_srvloop* l);

/* RFC 7301 3.2 / draft-ietf-moq-transport-19 3.1: 1 iff c negotiated a
 * raw-QUIC application ALPN (wired_srvboot_id.raw_alpns) -- the one bit
 * every native-QUIC binding transform below keys on (rawq_*). */
int srvrun_conn_is_raw(const srvrun_conn* c) {
  return c->s.sdrv.alpn == SALPN_RAW;
}

/* RFC 8899 4.4 / RFC 9000 14: the Maximum Packet Size c's DPLPMTUD search
 * has validated so far, in stream bytes per packet. pmtu_mps is the WHOLE
 * plaintext of the acked probe (srvrun_pmtu_probe_len seals exactly that
 * much PING+PADDING), so a slice gets that minus the worst-case STREAM
 * header: header + slice (+ any piggybacked ACK, srvrun_slice_ack_peek)
 * then never outgrows the validated probe's wire size, for any DCID length
 * (the same short header wraps both). Spending pmtu_mps on stream bytes
 * alone overshot every validated probe by the header -- 6 bytes on a
 * 1432-byte PPPoE path, where every full-size packet was then lost and
 * resent at the same size forever. Every send-sizing call site in this
 * file (wired_sendsess_arm's chunk argument, and the cwnd/credit gates that
 * must reserve room for the same chunk they will actually send) goes
 * through this one function instead of pmtu_mps directly, so a
 * srvrun_conn whose pmtu was never pmtu_init'd (validated == 0 --
 * every non-production `srvrun_conn c = {0}` test fixture in this file)
 * falls back to SRVRUN_CHUNK rather than underflowing pmtu_mps's
 * unsigned subtraction. */
usz srvrun_mps(const srvrun_conn* c) {
  return c->pmtu.validated ? pmtu_mps(&c->pmtu) - SRVRUN_STREAM_HDR_MAX
                           : SRVRUN_CHUNK;
}

/* The one process-wide instance wired_server_run/wired_server_run_opt drive
 * -- a single-threaded server needs exactly one. wired_srvrun_serve_env lets
 * a caller supply its own instead, for more than one independent loop. */
wired_srvrun_env g_srvrun_env;

void wired_srvrun_env_wt_usage(
    const wired_srvrun_env* env, wired_srvrun_wt_usage* out) {
  *out = env->wt_usage;
}

/* qlog packet_sent (pn/time are not tracked at this layer, so both are logged
 * as 0 — the record still proves a packet of `bytes` size went out). group_id
 * is c's slot (srvrun_conn.qlog_slot's doc). No-op when no qlog path is set.
 */
void srvrun_qlog_sent(const srvrun_cfg* cfg, const srvrun_conn* c, usz bytes) {
  char rec[128];
  usz  n;
  if (!cfg->qlog_path) {
    return;
  }
  n = wired_qlogevent_packet_sent(rec, sizeof rec, 0, c->qlog_slot, 0, bytes);
  if (n) {
    wired_qlog_append(cfg->qlog_path, wired_span_of((const u8*)rec, n));
  }
}

/* qlog packet_received (time not tracked at this layer; bytes is the whole
 * datagram, matching packet_sent's granularity). No-op without a qlog path.
 */
void srvrun_qlog_recv(
    const srvrun_cfg* cfg, const srvrun_conn* c, u64 pn, usz bytes) {
  char rec[128];
  usz  n;
  if (!cfg->qlog_path) {
    return;
  }
  n = wired_qlogevent_packet_received(
      rec, sizeof rec, 0, c->qlog_slot, pn, bytes);
  if (n) {
    wired_qlog_append(cfg->qlog_path, wired_span_of((const u8*)rec, n));
  }
}

/* qlog stream_frame_sent (RFC 9000 19.8): every STREAM frame this connection
 * sends, fired unconditionally including retransmits -- how many times an
 * offset range went out is itself the forensic signal this exists for. */
void srvrun_qlog_stream_sent(
    const srvrun_cfg*   cfg,
    const srvrun_conn*  c,
    u64                 now_ms,
    u64                 pn,
    const stream_frame* f) {
  char                            rec[192];
  usz                             n;
  wired_qlogevent_stream_frame_in in;
  if (!cfg->qlog_path) {
    return;
  }
  in = (wired_qlogevent_stream_frame_in){
      f->stream_id, f->offset, f->length, f->fin, pn};
  n = wired_qlogevent_stream_frame(
      rec, sizeof rec, now_ms, c->qlog_slot, "stream_frame_sent", &in);
  if (n) {
    wired_qlog_append(cfg->qlog_path, wired_span_of((const u8*)rec, n));
  }
}

srvrun_rxmark srvrun_rx_mark(const wired_srvloop* l) {
  return (srvrun_rxmark){
      l->app_rx_seen, l->app_rx_pn, l->hs_rx_seen, l->hs_rx_pn};
}

int srvrun_rx_app_adv(const srvrun_rxmark* m, const wired_srvloop* l) {
  return l->app_rx_seen != m->app_seen || l->app_rx_pn != m->app_pn;
}

static int srvrun_rx_hs_adv(const srvrun_rxmark* m, const wired_srvloop* l) {
  return l->hs_rx_seen != m->hs_seen || l->hs_rx_pn != m->hs_pn;
}

static int srvrun_rx_advanced(const srvrun_rxmark* m, const wired_srvloop* l) {
  return srvrun_rx_app_adv(m, l) || srvrun_rx_hs_adv(m, l);
}

/* The PN to log for this step: the 1-RTT space's if it moved, else the
 * Handshake space's. */
static u64 srvrun_rx_pn(const srvrun_rxmark* m, const wired_srvloop* l) {
  return srvrun_rx_app_adv(m, l) ? l->app_rx_pn : l->hs_rx_pn;
}

/* Log packet_received once per datagram that advanced a receive PN. */
void srvrun_note_recv(
    const srvrun_step_ctx* ctx,
    const srvrun_rxmark*   m,
    const srvrun_conn*     c,
    usz                    bytes) {
  if (srvrun_rx_advanced(m, &c->l)) {
    srvrun_qlog_recv(ctx->cfg, c, srvrun_rx_pn(m, &c->l), bytes);
  }
}
