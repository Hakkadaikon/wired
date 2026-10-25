#include "app/http3/server/srvrun/srvrun_impl.h"

static u64 srvrun_boot_budget(const srvrun_conn* c);
static int srvrun_path_validated(const srvrun_conn* c, int confirmed);
static usz srvrun_boot_sent_off(const srvrun_conn* c);

/* RFC 9000 8.1: this slot's remaining antiamp budget before path validation.
 * Once wired_server_is_confirmed the path is validated and the limit no
 * longer applies -- callers must check that first (this alone would just
 * report the frozen boot_rx/tx_bytes snapshot forever). */
static u64 srvrun_boot_budget(const srvrun_conn* c) {
  return antiamp_budget(c->boot_rx_bytes, c->boot_tx_bytes);
}

/* Send one datagram through the boot-phase antiamp gate, bumping
 * boot_tx_bytes (Initial and Handshake both count). The antiamp
 * budget check itself lives in the callers (srvrun_boot_gate_blocks) -- this
 * just sends and accounts, so a caller that already decided (e.g. because
 * the path is confirmed) never gets silently overruled here. */
void srvrun_boot_send(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_span pkt, const char* what) {
  srvrun_send(cfg, c, pkt, what);
  c->boot_tx_bytes += pkt.n;
}

/* RFC 9001 8.1: the client's address counts as validated once ANY Handshake
 * packet from it was successfully processed (hs_rx_seen -- decrypting one
 * proves it holds the Handshake keys, which only the real peer can derive),
 * not just once the whole handshake confirms. Without the early half, a
 * flight big enough to exhaust the 3x budget deadlocked against a client
 * whose own PTO probes (small Handshake PINGs) could never raise the budget
 * back above one full datagram -- the interop amplificationlimit case. */
static int srvrun_path_validated(const srvrun_conn* c, int confirmed) {
  return confirmed || c->l.hs_rx_seen;
}

/* The antiamp gate applies only until the path is validated. */
int srvrun_boot_gate_blocks(const srvrun_conn* c, int confirmed, usz want) {
  return !srvrun_path_validated(c, confirmed) && want > srvrun_boot_budget(c);
}

/* Send/resend the boot Initial through the same antiamp gate as the
 * Handshake flight (one decision point covers both). The very first
 * Initial always fits in practice (it never exceeds the client's own
 * first-Initial-derived budget, RFC 9000 14.1's 1200-byte floor); this stays
 * gated anyway so srvrun_boot_send has exactly one caller-side check to
 * reason about, not a special case for whoever calls it first. */
int srvrun_boot_send_initial(
    const srvrun_cfg* cfg, srvrun_conn* c, const char* what) {
  int confirmed = wired_server_is_confirmed(&c->s);
  /* RFC 9001 4.9.1: no Initial goes out once its keys are discarded */
  if (c->l.hs_rx_seen) {
    return 0;
  }
  if (srvrun_boot_gate_blocks(c, confirmed, c->boot_ini_len)) {
    return 0;
  }
  srvrun_boot_send(cfg, c, wired_span_of(c->boot_ini, c->boot_ini_len), what);
  return 1;
}

/* Offset into boot_hs where the first not-yet-sent datagram starts. */
static usz srvrun_boot_sent_off(const srvrun_conn* c) {
  usz off = 0;
  for (usz i = 0; i < c->boot_dgram_sent; i++) {
    off += c->boot_dgram_len[i];
  }
  return off;
}

/* RFC 9000 8.1: send boot_dgram_len[boot_dgram_sent..dgram_count) in order,
 * stopping at the first one that would exceed the antiamp budget -- the
 * rest stays held for a later round once more client bytes arrive.
 * Once the path is validated (confirmed) the limit is lifted and everything
 * remaining goes out in one pass. */
usz srvrun_boot_send_hs_gated(
    const srvrun_cfg* cfg, srvrun_conn* c, int confirmed) {
  usz off  = srvrun_boot_sent_off(c);
  usz sent = 0;
  while (c->boot_dgram_sent < c->boot_dgram_count) {
    wired_span pkt =
        wired_span_of(c->boot_hs + off, c->boot_dgram_len[c->boot_dgram_sent]);
    if (srvrun_boot_gate_blocks(c, confirmed, pkt.n)) {
      return sent;
    }
    srvrun_boot_send(cfg, c, pkt, "server Handshake flight sent\n");
    off += pkt.n;
    c->boot_dgram_sent++;
    sent++;
  }
  return sent;
}

/* Build this slot's own wired_srvboot_id: every field from cfg->id except
 * scid, which is c's own per-connection id — sharing cfg->id's fixed scid
 * across every slot would make every connection answer to the same DCID,
 * collapsing conntable's routing to a single slot (RFC 9000 5.1). */
wired_srvboot_id srvrun_slot_id(
    const wired_srvboot_id* base, const srvrun_conn* c) {
  wired_srvboot_id id = *base;
  id.scid             = c->scid;
  id.retry_odcid      = c->retry_odcid;
  id.retry_odcid_len  = c->retry_odcid_len;
  return id;
}

/* First datagram on this slot: cold-start the connection, register the
 * handler, send the server Initial and each Handshake flight datagram (the
 * Initial alone is padded to 1200 bytes, RFC 9000 14.1, so coalescing them
 * would exceed a 1500-byte MTU datagram). Returns 1 once the connection is
 * up. */
/* RFC 9000 10.2: answer an authenticated-but-unservable boot with an
 * Initial CONNECTION_CLOSE so the peer fails fast instead of retrying into
 * its handshake timeout. Always reports the boot failed. */
int srvrun_refuse(const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  u8  pkt[1500];
  u64 err = sdrv_last_error(&c->s.sdrv);
  usz n   = wired_srvboot_refusal(
      &c->boot, wired_span_of(c->scid, ctx->cfg->id->scid_len), err, pkt,
      sizeof pkt);
  WIRED_LOG("srvboot accept failed\n");
  if (err_is_crypto(err)) { /* RFC 8446 6.2: log the alert being sent */
    srvrun_log_close_alert("conn refused: handshake failed", err);
  }
  if (n) {
    srvrun_send(ctx->cfg, c, wired_span_of(pkt, n), "boot refused\n");
  }
  return 0;
}

/* RFC 9001 4.6.1: dg's boot accumulator held every 0-RTT datagram that
 * arrived before this boot's early keys existed (wired_srvboot_acc_feed) --
 * now that sdrv_early_keys is available (or the PSK/early data was
 * rejected, in which case wired_srvloop_recv's recv_zerortt simply fails
 * open and each step is a no-op), replay them through the exact same
 * real-wire step pair a later live 0-RTT/1-RTT datagram takes (RFC 9000
 * 12.3: 0-RTT opens into the shared App pn space) -- srvrun_sess_on_step is
 * what actually starts a response for a request wired_srvloop_dispatch
 * completed (srvrun_step_and_reap's own pairing); without it a 0-RTT-carried
 * request opens and ACKs but never gets answered. A peer CONNECTION_CLOSE
 * seen mid-replay (vanishingly unlikely this early) stops the replay rather
 * than stepping a freed slot. */
void srvrun_boot_flush_zerortt(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot) {
  usz n     = wired_srvboot_acc_zerortt_count(&c->boot);
  c->replay = 1;
  for (usz i = 0; i < n && !c->l.peer_closed; i++) {
    wired_span dg = wired_srvboot_acc_zerortt_take(&c->boot, i);
    srvrun_on_step(ctx, c, wired_mspan_of((u8*)dg.p, dg.n));
    srvrun_sess_on_step(ctx, slot);
  }
  c->replay = 0;
  /* spent: the confirmation-time flush (srvrun_flush_held_on_confirm) must
   * not replay what this call already stepped. */
  c->boot.zerortt_n = 0;
}
