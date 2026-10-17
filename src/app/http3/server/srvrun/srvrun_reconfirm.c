#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_note_dcid(
    srvrun_conn* c, wired_mspan dg, const srvrun_rxmark* mark);
static int  srvrun_leads_handshake(wired_mspan dg);
static void srvrun_reconfirm(const srvrun_step_ctx* ctx, srvrun_conn* c);
static usz  srvrun_seal_boot_probe(srvrun_conn* c, u8* out, usz cap);

/* Remember the server ID of a packet this step actually opened. */
static void srvrun_note_dcid(
    srvrun_conn* c, wired_mspan dg, const srvrun_rxmark* mark) {
  if (!srvrun_rx_app_adv(mark, &c->l) || !srvrun_dcid_room(c, dg)) {
    return;
  }
  bytes_memcpy(c->rx_dcid, dg.p + 1, c->s.sdrv.iscid_len);
}

/* RFC 9000 9: this step's path work, after decrypt and dedup and before
 * any other send of the step, so its ACK and data already use the new
 * path: peer IDs, path validation, the send-path decision, then answers to
 * the peer's PATH_CHALLENGEs. A step with no arrival address (ctx->peer 0)
 * has none. */
void srvrun_path_step(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    wired_mspan            dg,
    const srvrun_rxmark*   mark) {
  int kept;
  if (!ctx->peer) {
    return;
  }
  srvrun_path_seed(ctx->cfg, c);
  srvrun_path_take_cids(ctx->cfg, c);
  srvrun_apply_path_response(ctx->cfg, c);
  kept = srvrun_dcid_kept(c, dg);
  if (srvrun_rebind_due(ctx, c)) {
    srvrun_path_switch(ctx, c, kept);
  }
  srvrun_path_probe(ctx, c, kept);
  srvrun_note_dcid(c, dg, mark);
  srvrun_path_retire(ctx->cfg, c);
}

/* 1 if dg leads with a long-header Handshake packet (first byte 0b1110xxxx,
 * RFC 9000 17.2) -- readable without any keys. */
static int srvrun_leads_handshake(wired_mspan dg) {
  return dg.n != 0 && (dg.p[0] & 0xf0) == 0xe0;
}

/* RFC 9000 19.20: a confirmed connection receiving a Handshake-space probe
 * means the client never got the one-time confirmation datagram (it would
 * have dropped its Handshake keys otherwise) -- replay the cached
 * confirmation so HANDSHAKE_DONE still reaches it. Without this, one lost
 * confirmation datagram left the client PTO-retransmitting its Finished
 * until its own idle timeout (observed live under the interop runner's 30%
 * loss profile). */
static void srvrun_reconfirm(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u8                 out[512];
  wired_obuf         ob   = obuf_of(out, sizeof out);
  wired_srvloop_conn conn = {&c->l, &c->s};
  if (!wired_srvloop_reconfirm(&conn, &ob)) {
    return;
  }
  srvrun_send(
      ctx->cfg, c, wired_span_of(ob.p, ob.len), "confirmation resent\n");
}

void srvrun_reconfirm_on_hs_probe(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg) {
  if (!wired_server_is_confirmed(&c->s)) {
    return;
  }
  if (!srvrun_leads_handshake(dg)) {
    return;
  }
  srvrun_reconfirm(ctx, c);
}

/* RFC 9002 6.2.1: a datagram LEADING with a Handshake packet while c still
 * awaits confirmation is the client probing at the Handshake level -- it
 * demonstrably holds Handshake keys yet its handshake has not advanced, so
 * part of the cached flight is missing on its side. Replay the flight now
 * (antiamp-gated) instead of waiting out the boot PTO's exponential
 * backoff: five straight losses of a resumption flight's EE+Finished
 * datagram once pushed the next backoff replay past a neqo client's idle
 * timeout while its once-per-second probes went unanswered. booting is the
 * PRE-step state: a probe whose own processing just confirmed the
 * handshake (or tore the slot down) needs no replay -- awaiting_confirm
 * re-checks the POST-step state. */
int srvrun_hs_probe_pending(const srvrun_conn* c, int booting, wired_mspan dg) {
  return booting && srvrun_awaiting_confirm(c) && srvrun_leads_handshake(dg);
}

/* RFC 9002 6.2.4 while c awaits its peer's Finished with proof the peer
 * already finished (peer_at_onertt): replaying the cached flight is pure
 * waste -- every replay reuses its packet numbers, so a peer that has the
 * flight discards them all as duplicates and hears NOTHING (its idle timer
 * keeps running down), while each ~2KB replay burns the antiamp budget.
 * Both starved a live quiche connection to death: four replays exhausted
 * the 3x budget in under two seconds, the server then sat silent, and the
 * client idled out before its own (loss-inflated) Finished retransmission
 * timer fired. Send a minimal fresh 1-RTT PING instead: a NEW packet
 * number the peer actually processes -- resetting its idle timer and
 * eliciting an ack -- at a fraction of the budget, until the peer's own
 * timer redelivers the lost Finished. */
/* Seal one fresh 1-RTT PING for a peer that provably finished. The server
 * 1-RTT send keys are a 0.5-RTT derivation away (available since the
 * flight went out, wired_server_early_send_keys); the peer holds its 1-RTT
 * keys already, so this is the one packet it is guaranteed to process. */
static usz srvrun_seal_boot_probe(srvrun_conn* c, u8* out, usz cap) {
  static const u8       ping = 0x01; /* RFC 9000 19.2 */
  wired_obuf            ob   = obuf_of(out, cap);
  wired_srvloop_send_in sin  = {
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      c->l.tx_pn++,
      -1,
      wired_span_of(&ping, 1),
      0,
      0,
      0,
      0};
  if (!wired_server_early_send_keys(&c->s)) {
    return 0;
  }
  if (!wired_srvloop_send_onertt(&c->s, &sin, &ob)) {
    return 0;
  }
  return ob.len;
}

int srvrun_send_boot_probe(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u8  out[128];
  usz n = srvrun_seal_boot_probe(c, out, sizeof out);
  if (n == 0 || srvrun_boot_gate_blocks(c, 0, n)) {
    return 0;
  }
  srvrun_boot_send(ctx->cfg, c, wired_span_of(out, n), "boot keepalive sent\n");
  c->boot_pto_sent_ms = ctx->now_ms;
  c->boot_pto_count   = 0;
  return 1;
}
