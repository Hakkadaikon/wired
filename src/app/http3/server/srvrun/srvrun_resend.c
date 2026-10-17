#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_resend_hs(const srvrun_step_ctx* ctx, srvrun_conn* c);
static int srvrun_resend_flight_parts(
    const srvrun_step_ctx* ctx, srvrun_conn* c);
static int  srvrun_boot_pto_due(const srvrun_conn* c, u64 now_ms);
static void srvrun_boot_pto_resend(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int fired);
static void srvrun_boot_give_up_close(
    const srvrun_step_ctx* ctx, srvrun_conn* c);

/* RFC 9000 7.2: a retransmitting client's own DCID tells which flight half
 * it is missing, no decryption needed -- still addressing the ODCID means
 * it has never processed ANY server packet (the ServerHello must go out
 * first, or every other byte is undecryptable to it); addressing our SCID
 * means it has the ServerHello and is missing the Handshake half. */
void srvrun_boot_flip_from_dcid(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg) {
  wired_span dcid     = srvrun_dcid(dg, ctx->cfg->id->scid_len);
  c->boot_resend_flip = dcid.n == ctx->cfg->id->scid_len &&
                        ct_diffn(c->scid, dcid.p, dcid.n) == 0;
}

void srvrun_cold_start(const srvrun_step_ctx* ctx, int slot, wired_mspan dg) {
  /* Read BEFORE feeding: "was an HRR already out when this datagram
   * arrived" -- a fresh ClientHello1 that arms the HRR inside the feed
   * below must still take the partial-ack path, whose acc_allow side
   * effect admits the client's post-HRR DCID into the accumulator. */
  int had_hrr = srvrun_hrr_pending(&ctx->st->conns[slot]);
  int r       = srvrun_on_initial(ctx, slot, &ctx->st->conns[slot], dg);
  if (r != SRVRUN_BOOT_PENDING) {
    srvrun_open_done(ctx, slot, r);
    return;
  }
  /* RFC 8446 4.1.4: still pending with an HRR already out before this
   * datagram means it was a retransmitted ClientHello1 -- the HRR was
   * lost, so resend it (an ACK alone gives the client nothing). */
  if (had_hrr) {
    srvrun_resend_boot_flight(ctx, &ctx->st->conns[slot]);
    return;
  }
  srvrun_boot_partial_ack(ctx, slot);
}

/* RFC 9000 13.3: resend c's cached accept flight verbatim -- same Initial,
 * same Handshake datagrams -- instead of stepping dg through the confirmed-
 * connection path, where an Initial-keyed retransmit would just fail to
 * decrypt and get silently dropped. */
/* RFC 9002 6.2: a resend means the client is still waiting. Once the
 * WHOLE flight has gone out, any of its datagrams may be sitting in a
 * dropped packet, so rewind and replay from the start (without this a
 * single lost Handshake datagram deadlocked the handshake: the client
 * held the ServerHello and retransmitted its Initial forever, answered
 * only by verbatim Initial replays). While a tail is still withheld by
 * the antiamp budget, though, keep continuing FROM the tail -- an
 * unconditional rewind burned each budget grant re-sending datagrams
 * the client already had, and the amplificationlimit flight's tail
 * never went out at all (observed live: the client dropped the same
 * Handshake datagram 0 as a duplicate until its idle timeout). */
static int srvrun_resend_hs(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (c->boot_dgram_sent == c->boot_dgram_count) c->boot_dgram_sent = 0;
  return (int)srvrun_boot_send_hs_gated(
      ctx->cfg, c, wired_server_is_confirmed(&c->s));
}

/* Both halves of the cached flight, in this resend's budget-priority order
 * (boot_resend_flip: see its member doc). */
static int srvrun_resend_flight_parts(
    const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (c->boot_resend_flip)
    return srvrun_resend_hs(ctx, c) +
           srvrun_boot_send_initial(ctx->cfg, c, "server Initial resent\n");
  return srvrun_boot_send_initial(ctx->cfg, c, "server Initial resent\n") +
         srvrun_resend_hs(ctx, c);
}

int srvrun_resend_boot_flight(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  int sent;
  sent = srvrun_resend_flight_parts(ctx, c);
  c->boot_resend_flip ^= 1; /* alternate the priority for the NEXT replay */
  /* RFC 9000 8.1: nothing went out at all -- the whole flight is withheld
   * by the antiamp budget. Leave the PTO exactly as it was: a fully
   * blocked probe spent no budget and proved nothing, and re-arming (or
   * counting) it here burned the probe budget on silent no-ops until the
   * slot was torn down while the peer was still retrying (the interop
   * handshakecorruption stall). The deadline stays due, so the moment more
   * client bytes raise the budget (or a Handshake packet validates the
   * path) the very next tick resends for real. */
  if (!sent) return 0;
  /* boot PTO: something real went out -- push the boot PTO deadline so the
   * timer-driven probe does not also fire for the same round. */
  c->boot_pto_sent_ms = ctx->now_ms;
  c->boot_pto_count   = 0;
  return 1;
}

/* c is in the boot PTO's window at all -- up (accepted) but not
 * yet confirmed (srvrun_awaiting_confirm), and has actually sent a flight to
 * probe (boot_ini_len == 0 means nothing was ever cached, e.g. a slot still
 * mid-ClientHello-reassembly or a slot that failed to boot). */
int srvrun_boot_pto_waiting(const srvrun_conn* c) {
  return srvrun_boot_probe_armed(c) && c->boot_ini_len != 0;
}

/* RFC 9002 6.2: 1 once c is in the boot PTO's window AND now_ms has crossed
 * its deadline (scaled by boot_pto_count's backoff, same formula
 * srvrun_sess_pto_due uses for an in-flight response, applied to the boot
 * flight's own single sent timestamp instead of a wired_sendsess log). */
static int srvrun_boot_pto_due(const srvrun_conn* c, u64 now_ms) {
  u64 wait = u64_min(
      srvrun_pto_deadline_ms(c, c->boot_pto_count), SRVRUN_BOOT_RESEND_CAP_MS);
  if (!srvrun_boot_pto_waiting(c)) return 0;
  return now_ms >= c->boot_pto_sent_ms + wait;
}

/* Resend the boot flight for a fired probe and restore its post-resend probe
 * count: srvrun_resend_boot_flight itself resets boot_pto_count to 0 (any
 * real send re-arms the deadline), which would erase this probe's own
 * budget spend -- put it back to `fired` right after so consecutive timer
 * probes keep climbing instead of resetting every single one. */
static void srvrun_boot_pto_resend(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int fired) {
  if (!srvrun_boot_probe_or_replay(ctx, c)) return;
  c->boot_pto_count = fired;
}

/* RFC 9002 6.2 boot-stage PTO: while awaiting confirm with a flight already
 * sent, resend the cached boot_ini/boot_hs verbatim once the deadline
 * elapses -- quic-interop-runner's handshakeloss/handshakecorruption drop the
 * server's first flight often enough that waiting on a client-triggered
 * retransmit alone (srvrun_resend_boot_flight) leaves the handshake to time
 * out. Tears the slot down once the boot probe budget is spent
 * (SRVRUN_BOOT_PTO_MAX -- sized for the capped cadence; srvrun_pto_slot
 * keeps its own SRVRUN_PTO_MAX for in-flight responses, and the two are
 * never both active for the same slot). */
/* RFC 9000 10.2: tell a still-listening peer this handshake is abandoned
 * before reclaiming its slot. Only a peer that provably finished
 * (peer_at_onertt) can read the 1-RTT close -- and that peer is exactly
 * the one otherwise left pinging a dead slot through its own idle timeout
 * and a multi-second draining period (observed live: one such zombie
 * connection burned two minutes of a 300s multiconnect budget). A keyless
 * peer cannot be told anything it can decrypt, so nothing is sent. */
static void srvrun_boot_give_up_close(
    const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (!c->peer_at_onertt) return;
  (void)wired_server_early_send_keys(&c->s); /* 0.5-RTT seal, RFC 9001 4.9 */
  srvrun_send_app_close(ctx->cfg, c, 0, wired_span_of((const u8*)0, 0));
}

void srvrun_boot_pto_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c     = &ctx->st->conns[slot];
  int          fired = c->boot_pto_count + 1;
  if (!srvrun_boot_pto_due(c, ctx->now_ms)) return;
  if (fired >= SRVRUN_BOOT_PTO_MAX) {
    srvrun_boot_give_up_close(ctx, c);
    srvrun_note_ghost(ctx, c); /* swallow its closing-period stragglers */
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
    return;
  }
  srvrun_boot_pto_resend(ctx, c, fired);
}
