#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_boot_give_up_close(
    const srvrun_step_ctx* ctx, srvrun_conn* c);

/* c is in the boot PTO's window at all -- up (accepted) but not
 * yet confirmed (srvrun_awaiting_confirm), and has actually sent a flight to
 * probe (boot_ini_len == 0 means nothing was ever cached, e.g. a slot still
 * mid-ClientHello-reassembly or a slot that failed to boot). */
int srvrun_boot_pto_waiting(const srvrun_conn* c) {
  return srvrun_boot_probe_armed(c) && c->boot_ini_len != 0;
}

/* RFC 9002 A.8: the Initial space has ack-eliciting data in flight. */
static int srvrun_boot_ini_armed(const srvrun_conn* c) {
  return srvrun_boot_pto_waiting(c) && !srvrun_boot_ini_done(c);
}

/* A Handshake datagram already sent and not acknowledged. Masking with the
 * sent bits also drops an ACK of a number never sent.
 * shortcut: such an ACK is ignored, not closed with PROTOCOL_VIOLATION
 * (RFC 9000 13.1 SHOULD); add the close if a peer is ever seen doing it. */
static u32 srvrun_boot_hs_sent(const srvrun_conn* c) {
  return (1u << c->boot_dgram_sent) - 1; /* <= WIRED_SRVBOOT_FLIGHT_MAX */
}

static int srvrun_boot_hs_unacked(const srvrun_conn* c) {
  return (srvrun_boot_hs_sent(c) & ~c->l.hs_acked) != 0;
}

/* RFC 9002 A.8: the Handshake space has ack-eliciting data in flight -- or
 * the peer provably finished (peer_at_onertt), when the Handshake timer
 * paces the 1-RTT keepalive (srvrun_send_boot_probe) instead. */
int srvrun_boot_hs_armed(const srvrun_conn* c) {
  return srvrun_boot_pto_waiting(c) &&
         (srvrun_boot_hs_unacked(c) || c->peer_at_onertt);
}

/* RFC 9002 A.8 GetPtoTimeAndSpace: the armed space with the earliest send
 * time, -1 for none. With both armed the comparison yields the index
 * itself (SRVRUN_BOOT_SP_HS = 1 only when strictly earlier: a tie goes to
 * Initial, A.8's loop order). */
static int srvrun_boot_earliest(const srvrun_conn* c) {
  const int pick[4] = {
      -1, SRVRUN_BOOT_SP_INI, SRVRUN_BOOT_SP_HS,
      c->boot_sent_ms[SRVRUN_BOOT_SP_HS] < c->boot_sent_ms[SRVRUN_BOOT_SP_INI]};
  return pick[srvrun_boot_ini_armed(c) | srvrun_boot_hs_armed(c) << 1];
}

/* RFC 9002 6.2.1: the PTO period, doubled per pto_count, without
 * max_ack_delay -- the peer does not delay Initial or Handshake ACKs --
 * and capped at SRVRUN_BOOT_RESEND_CAP_MS. */
/* shortcut: SRVRUN_BOOT_RESEND_CAP_MS (300 ms) is below the kInitialRtt
 * period (~1 s), so before an RTT sample the doubling has no effect and
 * probes go every 300 ms; revisit if the boot flight ever gets an RTT
 * sample before confirmation, or the cap is removed. */
static u64 srvrun_boot_pto_wait(const srvrun_conn* c) {
  pto_rtt rtt = {c->rtt.smoothed_rtt, c->rtt.rttvar};
  return u64_min(
      pto_duration(rtt, 0, (u32)c->boot_pto_count) / 1000,
      SRVRUN_BOOT_RESEND_CAP_MS);
}

/* The space whose PTO has expired at now_ms, or -1. */
static int srvrun_boot_pto_due(const srvrun_conn* c, u64 now_ms) {
  int sp = srvrun_boot_earliest(c);
  if (sp < 0) {
    return -1;
  }
  return now_ms >= c->boot_sent_ms[sp] + srvrun_boot_pto_wait(c) ? sp : -1;
}

/* The 1-RTT keepalive for a peer that provably finished (its doc). */
static int srvrun_boot_keepalive(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  return c->peer_at_onertt && srvrun_send_boot_probe(ctx, c);
}

/* RFC 9002 6.2.4: "An endpoint SHOULD include new data in packets that are
 * sent on PTO expiration. Previously sent data MAY be sent if no new data
 * can be sent" -- the tail the antiamp gate held first, else the
 * unacknowledged datagrams already sent; up to two either way. */
static int srvrun_boot_hs_resend_probe(
    const srvrun_step_ctx* ctx, srvrun_conn* c) {
  int sent = srvrun_boot_send_hs_upto(
                 ctx->cfg, c, wired_server_is_confirmed(&c->s),
                 SRVRUN_BOOT_PROBE_DGRAMS) != 0 ||
             srvrun_boot_resend_hs(ctx->cfg, c, SRVRUN_BOOT_PROBE_DGRAMS) != 0;
  return srvrun_boot_mark(ctx, c, SRVRUN_BOOT_SP_HS, sent);
}

/* RFC 9002 6.2.4 for the Handshake space: the keepalive for a finished
 * peer, else Handshake data (srvrun_boot_hs_resend_probe, at most
 * SRVRUN_BOOT_PROBE_DGRAMS datagrams), else -- the budget fits none -- a
 * Handshake PING. Also the answer to a client's own Handshake probe
 * (srvrun_claim.c). */
int srvrun_boot_hs_pto_probe(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  return srvrun_boot_keepalive(ctx, c) || srvrun_boot_hs_resend_probe(ctx, c) ||
         srvrun_boot_hs_probe(ctx, c);
}

/* RFC 9002 6.2.4: probe the expired space only. The Initial probe carries
 * the ServerHello and no Handshake data: 6.2.4 says a sender SHOULD also
 * send from the other spaces with data in flight, but until the client
 * acknowledges the ServerHello every Handshake byte is undecryptable to it
 * and spends the RFC 9000 8.1 budget the next Initial needs (interop: the
 * ServerHello Initial lost four times in a row while the budget went to
 * Handshake replays). The Handshake space's own PTO sends its data. A
 * probe the antiamp budget blocks entirely spends nothing: the backoff
 * stays and the deadline stays due (srvrun_resend_boot_flight's note). */
static void srvrun_boot_pto_probe(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int sp, int fired) {
  static int (*const probe[])(const srvrun_step_ctx*, srvrun_conn*) = {
      srvrun_resend_ini, srvrun_boot_hs_pto_probe};
  if (probe[sp](ctx, c)) {
    c->boot_pto_count = fired; /* RFC 9002 6.2.1: the backoff doubles */
  }
}

/* RFC 9000 10.2: tell a still-listening peer this handshake is abandoned
 * before reclaiming its slot. Only a peer that provably finished
 * (peer_at_onertt) can read the 1-RTT close -- and that peer is exactly
 * the one otherwise left pinging a dead slot through its own idle timeout
 * and a multi-second draining period (observed live: one such zombie
 * connection burned two minutes of a 300s multiconnect budget). A keyless
 * peer cannot be told anything it can decrypt, so nothing is sent. */
static void srvrun_boot_give_up_close(
    const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (!c->peer_at_onertt) {
    return;
  }
  (void)wired_server_early_send_keys(&c->s); /* 0.5-RTT seal, RFC 9001 4.9 */
  srvrun_send_app_close(ctx->cfg, c, 0, wired_span_of((const u8*)0, 0));
}

/* RFC 9002 6.2 boot-stage PTO, one timer over the Initial and Handshake
 * spaces (6.2.1): while awaiting confirm, probe the space whose deadline
 * expired -- quic-interop-runner's handshakeloss/handshakecorruption drop
 * the server's flight often enough that waiting on a client-triggered
 * retransmit alone (srvrun_resend_boot_flight) leaves the handshake to time
 * out. Tears the slot down once the boot probe budget is spent
 * (SRVRUN_BOOT_PTO_MAX -- sized for the capped cadence; srvrun_pto_slot
 * keeps its own SRVRUN_PTO_MAX for in-flight responses, and the two are
 * never both active for the same slot). */
void srvrun_boot_pto_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c     = &ctx->st->conns[slot];
  int          fired = c->boot_pto_count + 1;
  int          sp    = srvrun_boot_pto_due(c, ctx->now_ms);
  if (sp < 0) {
    return;
  }
  if (fired >= SRVRUN_BOOT_PTO_MAX) {
    srvrun_boot_give_up_close(ctx, c);
    srvrun_note_ghost(ctx, c); /* swallow its closing-period stragglers */
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
    return;
  }
  srvrun_boot_pto_probe(ctx, c, sp, fired);
}

/* RFC 9002 6.2.1: "The PTO backoff factor is reset when an acknowledgment
 * is received" -- one this step that newly acknowledges a Handshake packet
 * actually sent (RFC 9002 A.7; an ACK of a number never sent, which
 * hs_acked also records, resets nothing); RFC 9002 6.2.2 / A.11: or the
 * Initial keys went this step (RFC 9001 4.9.1: the first Handshake packet
 * was processed, hs_rx_seen rose), after which only the Handshake space
 * arms the timer. */
static int srvrun_boot_backoff_reset(
    const srvrun_conn* c, const srvrun_rxmark* m) {
  return (!m->hs_seen && c->l.hs_rx_seen) ||
         (c->l.hs_acked & ~m->hs_acked & srvrun_boot_hs_sent(c)) != 0;
}

void srvrun_boot_on_rx(srvrun_conn* c, const srvrun_rxmark* m) {
  if (srvrun_boot_backoff_reset(c, m)) {
    c->boot_pto_count = 0;
  }
}
