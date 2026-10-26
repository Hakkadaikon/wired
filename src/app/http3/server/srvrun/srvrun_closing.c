#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_tick_slot(const srvrun_step_ctx* ctx, int slot);
static int  srvrun_boot_zerortt(srvrun_conn* c, wired_mspan dg);
static int  srvrun_unconfirmed_up(const srvrun_conn* c);
static int  srvrun_boot_hold_early(srvrun_conn* c, wired_mspan dg);
static int  srvrun_boot_has_pending_tail(const srvrun_conn* c);
__attribute__((unused)) static void srvrun_test_force_challenge_rng_fail(int v);

/* RFC 9000 10.2 / 10.2.1: a closing slot does no tick work (no probe,
 * resend, or datagram -- only its CONNECTION_CLOSE may go out, and only in
 * answer to a packet) and is reaped once its closing period is over, its
 * scid remembered so the peer's stragglers draw no stateless reset. 1 iff
 * the slot is closing. */
int srvrun_closing_tick(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (!c->closing) {
    return 0;
  }
  if (srvrun_close_reap_due(c, ctx->now_ms)) {
    srvrun_note_ghost(ctx, c);
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
  }
  return 1;
}

/* One slot's tick work on a poll timeout: post-confirm PTO probe/teardown,
 * boot-stage PTO probe/teardown (mutually exclusive -- srvrun_pto_armed
 * requires confirmation, and
 * srvrun_boot_pto_waiting requires !confirmed), then flush any queued
 * broadcast DATAGRAM -- split out so the loop below stays flat. */
static void srvrun_tick_slot(const srvrun_step_ctx* ctx, int slot) {
  if (srvrun_closing_tick(ctx, slot)) {
    return;
  }
  ctx->st->conns[slot].l.now_ms = ctx->now_ms; /* sends below record it */
  srvrun_loss_timer_slot(ctx, slot);
  srvrun_ack_tick_slot(ctx, slot);
  srvrun_pto_slot(ctx, slot);
  srvrun_boot_pto_slot(ctx, slot);
  srvrun_grant_retry_slot(ctx, slot);
  srvrun_rst_retry_slot(ctx, slot);
  srvrun_dg_slot(ctx, slot);
  srvrun_wt_app_pending_slot(ctx, slot);
  srvrun_path_tick(ctx, &ctx->st->conns[slot]);
}

/* A poll timeout with responses or broadcast DATAGRAMs in flight: fire the
 * probe/flush pass over every waiting slot. */
void srvrun_fire_ptos(const srvrun_cfg* cfg, srvrun_state* st) {
  srvrun_step_ctx ctx = {cfg, 0, st, clock_mono_ms(), 0};
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    srvrun_tick_slot(&ctx, (int)i);
  }
}

/* RFC 9001 4.6.1: dg is a 0-RTT datagram arriving on a slot still mid-boot
 * (not up yet) -- this boot's early keys do not exist yet to open it with,
 * so it goes straight into the boot accumulator's own 0-RTT buffer
 * (wired_srvboot_acc_feed's own dispatch) for srvrun_boot_flush_zerortt to
 * replay once the accumulator's Initial reassembly completes and keys are
 * derived. A slot already up (c->up) instead takes the live 1-RTT/0-RTT
 * step path (srvrun_step_and_reap), which opens directly with the
 * connection's now-installed keys. */
static int srvrun_boot_zerortt(srvrun_conn* c, wired_mspan dg) {
  if (c->up || !wired_srvboot_is_zerortt(dg.p, dg.n)) {
    return 0;
  }
  wired_srvboot_acc_feed(&c->boot, dg);
  return 1;
}

/* 1 if dg wears a short (1-RTT) header. */
int srvrun_short_header(wired_mspan dg) {
  return dg.n != 0 && (dg.p[0] & 0x80) == 0;
}

/* RFC 9001 5.7: a 1-RTT datagram arriving after the flight went out but
 * before the client Finished is verified MUST NOT be processed yet -- hold
 * it for the confirmation-time replay (srvrun_flush_held_on_confirm)
 * instead of dropping it un-ACKed: quinn sends its request the moment its
 * own handshake completes and never retransmits the STREAM bytes when no
 * ACK arrives, so a dropped early request was lost for good. */
/* 1 while c has sent its flight but the client Finished is unverified. */
static int srvrun_unconfirmed_up(const srvrun_conn* c) {
  return c->up && !wired_server_is_confirmed(&c->s);
}

int srvrun_boot_early_onertt(srvrun_conn* c, wired_mspan dg) {
  if (!srvrun_unconfirmed_up(c) || !srvrun_short_header(dg)) {
    return 0;
  }
  wired_srvboot_acc_hold(&c->boot, dg);
  c->peer_at_onertt = 1; /* the client finished: 1-RTT proves it */
  return 1;
}

/* Early app data this boot cannot process yet, held for replay: 0-RTT
 * before keys exist, or 1-RTT before the client Finished verified. */
static int srvrun_boot_hold_early(srvrun_conn* c, wired_mspan dg) {
  return srvrun_boot_zerortt(c, dg) || srvrun_boot_early_onertt(c, dg);
}

/* dg is a fresh cold-start Initial (srvrun_cold_start), a retransmit of one
 * already accepted but not yet confirmed (srvrun_resend_boot_flight), or
 * early app data held for later replay (srvrun_boot_hold_early) --
 * dispatched to whichever applies. Returns 1 if any handled dg. */
int srvrun_serve_boot(const srvrun_step_ctx* ctx, int slot, wired_mspan dg) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (srvrun_is_new(c, dg)) {
    srvrun_cold_start(ctx, slot, dg);
    return 1;
  }
  if (srvrun_is_boot_retransmit(c, dg)) {
    srvrun_boot_flip_from_dcid(ctx, c, dg);
    srvrun_resend_boot_flight(ctx, c);
    return 1;
  }
  return srvrun_boot_hold_early(c, dg);
}

/* c is up, unconfirmed, and still has boot datagrams the antiamp gate held
 * back -- the condition srvrun_boot_release_pending gates its send on. */
static int srvrun_boot_has_pending_tail(const srvrun_conn* c) {
  if (!c->up || wired_server_is_confirmed(&c->s)) {
    return 0;
  }
  return c->boot_dgram_sent < c->boot_dgram_count;
}

/* RFC 9000 8.1: a slot with boot datagrams still held back by the antiamp
 * gate gets another release attempt on EVERY datagram it receives before
 * confirmation -- not just an all-Initial retransmit (srvrun_is_boot_
 * retransmit's narrower trigger). The real amplificationlimit trace shows
 * the client ACKing Handshake packets it already has (not resending its
 * Initial) while waiting for the still-held-back tail; without this, that
 * growing boot_rx_bytes budget never gets spent and the tail sits forever. */
void srvrun_boot_release_pending(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (srvrun_boot_has_pending_tail(c)) {
    srvrun_boot_send_hs_gated(ctx->cfg, c, 0);
  }
}

/* Test-only override forcing challenge_generate to behave as if
 * the RNG failed, the same override-flag shape as srvrun_test_set_shutdown
 * above -- getrandom(2) failing is not practically triggerable from a test,
 * so this is the seam. Always reset to 0 after the owning test (see
 * srvrun_test_set_shutdown's own callers for the convention). */
static int g_srvrun_path_challenge_force_fail;

__attribute__((unused)) static void srvrun_test_force_challenge_rng_fail(
    int v) {
  g_srvrun_path_challenge_force_fail = v;
}

/* RFC 9000 8.2.2: generate one 8-byte PATH_CHALLENGE data. Returns 0 (and
 * writes nothing meaningful to data) on RNG failure, so the caller never
 * sends an unpredictable-in-name-only (actually zero or stale) challenge. */
int srvrun_gen_path_challenge(u8 data[PATH_DATA]) {
  if (g_srvrun_path_challenge_force_fail) {
    return 0;
  }
  return challenge_generate(data);
}
