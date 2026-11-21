#include "app/http3/server/srvloop/recv.h"
#include "app/http3/server/srvrun/srvrun_impl.h"
#include "transport/packet/frame/pipeline/framewalk.h"

static int srvrun_resend_hs(const srvrun_step_ctx* ctx, srvrun_conn* c);
static int srvrun_resend_flight_parts(
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

/* RFC 9002 A.8 time_of_last_ack_eliciting_packet[sp]: restart space sp's
 * clock when something went out in it. Returns sent. */
int srvrun_boot_mark(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int sp, int sent) {
  if (sent) {
    c->boot_sent_ms[sp] = ctx->now_ms;
  }
  return sent;
}

/* The ServerHello Initial again, unless acknowledged or discarded
 * (srvrun_boot_send_initial). */
int srvrun_resend_ini(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  return srvrun_boot_mark(
      ctx, c, SRVRUN_BOOT_SP_INI,
      srvrun_boot_send_initial(ctx->cfg, c, "server Initial resent\n"));
}

/* RFC 9000 13.3: resend c's cached accept flight -- same Initial, same
 * Handshake datagrams -- instead of stepping dg through the confirmed-
 * connection path, where an Initial-keyed retransmit would just fail to
 * decrypt and get silently dropped. */
/* RFC 9002 6.2: a resend means the client is still waiting. Once the
 * WHOLE flight has gone out, any datagram the client has not acknowledged
 * may be sitting in a dropped packet, so every unacknowledged one goes
 * again (without this a single lost Handshake datagram deadlocked the
 * handshake: the client held the ServerHello and retransmitted its Initial
 * forever, answered only by verbatim Initial replays). While a tail is
 * still withheld by the antiamp budget, though, keep continuing FROM the
 * tail -- re-sending from the start burned each budget grant on datagrams
 * the client already had, and the amplificationlimit flight's tail never
 * went out at all (observed live: the client dropped the same Handshake
 * datagram 0 as a duplicate until its idle timeout). */
static int srvrun_resend_hs(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  usz n;
  if (c->boot_dgram_sent < c->boot_dgram_count) {
    n = srvrun_boot_send_hs_gated(
        ctx->cfg, c, wired_server_is_confirmed(&c->s));
  } else {
    n = srvrun_boot_resend_hs(ctx->cfg, c, WIRED_SRVBOOT_FLIGHT_MAX);
  }
  return srvrun_boot_mark(ctx, c, SRVRUN_BOOT_SP_HS, n != 0);
}

/* Both halves of the cached flight, in this resend's budget-priority order
 * (boot_resend_flip: see its member doc). */
static int srvrun_resend_flight_parts(
    const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (c->boot_resend_flip) {
    return srvrun_resend_hs(ctx, c) + srvrun_resend_ini(ctx, c);
  }
  return srvrun_resend_ini(ctx, c) + srvrun_resend_hs(ctx, c);
}

/* RFC 9002 6.2.4 / RFC 9000 8.1: every cached datagram exceeds the
 * remaining antiamp budget, but a fresh Handshake PING still fits -- send it
 * so the client answers with a Handshake packet, which validates its
 * address (hs_rx_seen). Without it the server fell silent with budget left
 * and msquic idled out while the amplificationlimit testcase dropped its
 * own probes. */
int srvrun_boot_hs_probe(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  static const u8 ping = 0x01; /* RFC 9000 19.2 */
  u8              out[128];
  wired_obuf      ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_hs_frames(c, wired_span_of(&ping, 1), &ob)) {
    return 0;
  }
  if (srvrun_boot_gate_blocks(c, wired_server_is_confirmed(&c->s), ob.len)) {
    c->l.hs_tx_pn--; /* never sent, so the number stays unused */
    return 0;
  }
  srvrun_boot_send(
      ctx->cfg, c, wired_span_of(out, ob.len), "boot Handshake probe sent\n");
  return srvrun_boot_mark(ctx, c, SRVRUN_BOOT_SP_HS, 1);
}

int srvrun_resend_boot_flight(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  int sent;
  sent = srvrun_resend_flight_parts(ctx, c) || srvrun_boot_hs_probe(ctx, c);
  c->boot_resend_flip ^= 1; /* alternate the priority for the NEXT replay */
  /* RFC 9000 8.1: nothing went out at all -- the whole flight is withheld
   * by the antiamp budget. Leave the PTO exactly as it was: a fully
   * blocked probe spent no budget and proved nothing, and re-arming (or
   * counting) it here burned the probe budget on silent no-ops until the
   * slot was torn down while the peer was still retrying (the interop
   * handshakecorruption stall). The deadline stays due, so the moment more
   * client bytes raise the budget (or a Handshake packet validates the
   * path) the very next tick resends for real. */
  if (!sent) {
    return 0;
  }
  /* something real went out (each part restarted its own space's clock):
   * the client is still there, so the backoff restarts too. */
  c->boot_pto_count = 0;
  return 1;
}

/* RFC 9002 A.7: pl acknowledges the ServerHello Initial (pn) for the first
 * time -- only a newly acknowledged packet resets the backoff. */
static int srvrun_boot_ini_newly_acked(
    const srvrun_conn* c, wired_span pl, u64 pn) {
  return !c->boot_ini_acked &&
         ((u64)srvloop_acked_bits(pl) >> u64_min(pn, 63) & 1);
}

/* RFC 9002 A.7: dg is a client Initial; if it opens, note whether it
 * acknowledges the ServerHello Initial (pn ini_next_pn - 1, srvrun_boot_up).
 * Opening decrypts dg in place -- it is consumed here.
 * shortcut: only numbers below 32 are seen (srvloop_acked_bits); a flight
 * Initial past 31 partial ACKs stays in flight until the Initial keys go,
 * record the Largest Acknowledged if that ever happens. */
static int srvrun_boot_ini_ack_only(srvrun_conn* c, wired_mspan dg) {
  wired_srvloop_recv_in  in = {dg, 0, 0};
  wired_srvloop_recv_out out;
  u64                    pn = c->ini_next_pn - 1;
  if (!wired_srvloop_recv(&c->s, &in, &out)) {
    return 0;
  }
  if (srvrun_boot_ini_newly_acked(c, out.payload, pn)) {
    c->boot_ini_acked = 1;
    c->boot_pto_count = 0; /* RFC 9002 6.2.1: reset on an acknowledgment */
  }
  return !framewalk_kinds_ack_eliciting(framewalk_kinds(out.payload));
}

/* A client Initial on a slot whose flight is out: an ACK-only one is no
 * retransmission request (RFC 9002 6.2: loss detection and the PTO drive
 * retransmission), anything else (a ClientHello retransmit, a PING) is
 * answered with the flight (srvrun_resend_boot_flight). An Initial that
 * does not open is treated as a retransmit, as before. */
void srvrun_boot_on_client_initial(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg) {
  srvrun_boot_flip_from_dcid(ctx, c, dg);
  if (srvrun_boot_ini_ack_only(c, dg)) {
    /* RFC 9000 8.1: its bytes raised the budget a held tail may need */
    srvrun_boot_release_pending(ctx, c);
    return;
  }
  srvrun_resend_boot_flight(ctx, c);
}
