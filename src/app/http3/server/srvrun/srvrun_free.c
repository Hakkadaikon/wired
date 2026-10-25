#include "app/http3/server/srvrun/srvrun_impl.h"
#include "transport/conn/lifecycle/closelife/idlefloor.h"

static int srvrun_pkt_is_initial(wired_mspan dg, usz off);
static int srvrun_pkts_all_initial(wired_mspan dg, const usz* offs, usz n);
static int srvrun_dgram_all_initial(wired_mspan dg);
static int srvrun_idle_due(const srvrun_conn* c, u64 now_ms);

/* RFC 8446 4.1.4: a HelloRetryRequest went out (its Initial is cached in
 * boot_ini) while the connection is not up yet. The flight-retransmission
 * machinery must treat this exactly like an unconfirmed accept flight, or
 * a lost HRR is never resent and the client just retransmits its
 * ClientHello1 against a server that only ever ACKs. */
int srvrun_hrr_pending(const srvrun_conn* c) {
  return !c->up && c->boot_ini_len != 0;
}

/* Either boot-phase state with a resendable flight cached: accept flight
 * out but unconfirmed, or HRR out but not up. */
int srvrun_boot_probe_armed(const srvrun_conn* c) {
  return srvrun_awaiting_confirm(c) || srvrun_hrr_pending(c);
}

/* 1 if the packet at dg.p[off] wears a long header of the Initial type
 * (RFC 9000 17.2.2 for v1, RFC 9369 3.2 for v2 -- the type-bit layout is
 * version-dependent, so this reads the packet's own Version field rather
 * than assuming v1's). */
static int srvrun_pkt_is_initial(wired_mspan dg, usz off) {
  if (off + 5 > dg.n) {
    return 0;
  }
  return packet_long_type(dg.p[off], be_get_be32(dg.p + off + 1)) == PT_INITIAL;
}

/* 1 if every packet at offs[0..n) within dg is an Initial. */
static int srvrun_pkts_all_initial(wired_mspan dg, const usz* offs, usz n) {
  for (usz i = 0; i < n; i++) {
    if (!srvrun_pkt_is_initial(dg, offs[i])) {
      return 0;
    }
  }
  return 1;
}

/* RFC 9000 12.2: 1 if dg parses as coalesced packets that are ALL Initials.
 * A client's second flight coalesces an Initial (ACK) with a Handshake
 * packet carrying its Finished -- such a datagram is handshake progress, not
 * a bare first-flight retransmit, and must never be swallowed by the cached
 * boot-flight resend (that discards the Finished and wedges the handshake
 * unconfirmed; curl connects and then stalls on its request). */
static int srvrun_dgram_all_initial(wired_mspan dg) {
  const u8* pkts[4];
  usz       offs[4], lens[4], n;
  pktlist   pl = {pkts, offs, lens, 4};
  n            = udploop_split(wired_span_of(dg.p, dg.n), &pl);
  return n != 0 && srvrun_pkts_all_initial(dg, offs, n);
}

/* RFC 9000 13.3: an all-Initial datagram on a slot already up, not yet
 * confirmed, and not eligible to (re)cold-start (srvrun_is_new said no) is
 * the client retransmitting its first flight because the server's reply
 * hasn't reached it yet -- not a new connection attempt. A datagram that
 * coalesces anything beyond Initials (srvrun_dgram_all_initial says no)
 * carries handshake progress and takes the step path instead. */
int srvrun_is_boot_retransmit(const srvrun_conn* c, wired_mspan dg) {
  if (!srvrun_awaiting_confirm(c)) {
    return 0;
  }
  if (c->boot_ini_len == 0) {
    return 0;
  }
  return srvrun_dgram_all_initial(dg);
}

/* Free slot i: drop its table entry and clear its connection's up flag (the
 * shutdown drain accounting then counts it as drained).
 *
 * Connection teardown (peer CONNECTION_CLOSE, boot failure, or idle sweep
 * -- the 3 call sites below) also ends every WebTransport session the
 * connection still carries. A CONNECT stream's own FIN/RESET ends just its
 * session while the connection lives on (srvrun_close_wt_on_stream_close). */
/* Release every resp[] slot's bigbuf pool row: a streaming response
 * mid-flight when its connection tears down (idle timeout, boot failure,
 * CONNECTION_CLOSE) would otherwise leave its claimed row permanently
 * marked in_use -- srvrun_open_slot only zeroes the conn struct on reuse, it
 * never touches wired_srvbigbuf's own in_use[] bookkeeping. */
void srvrun_free_bigbuf_rows(wired_srvrun_env* env, srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    srvrun_resp_release_bigbuf(env, &c->resp[i]);
  }
}

/* Close every open WT session slot on c, not just one -- whole-connection
 * teardown must never leave a session behind. */
void srvrun_close_all_wt(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    if (!(*srvrun_wt_active_slot(c, i))) {
      continue;
    }
    srvrun_notify_wt_close(cfg, srvrun_wt_slot(c, i));
    wired_wt_session_close(srvrun_wt_slot(c, i));
    (*srvrun_wt_active_slot(c, i)) = 0;
  }
}

void srvrun_free_slot(const srvrun_cfg* cfg, srvrun_state* st, int i) {
  srvrun_conn* c = &st->conns[i];
  srvrun_close_all_wt(cfg, c);
  wired_srvloop_abort_bodies(&c->l); /* bodies cut short by the close */
  srvrun_free_bigbuf_rows(cfg->env, c);
  conntable_remove(st->table, WIRED_CONNTABLE_CAP, i);
  c->up = 0;
  /* the departed connection's handshake and traffic keys leave memory with
   * it, not when (or if) the slot is next claimed */
  bytes_wipe(&c->s, sizeof c->s);
  wired_srvboot_acc_reset(&c->boot);
  /* RFC 9000 8.1 antiamp state is per-attempt -- a slot reused for a fresh
   * boot must not inherit a stale budget from the connection it replaces.
   * srvrun_boot_finish re-seeds boot_dgram_count/sent on the next
   * accept; this covers the window before that. */
  c->boot_rx_bytes   = 0;
  c->boot_tx_bytes   = 0;
  c->boot_dgram_sent = 0;
  /* srvrun_hrr_pending reads boot_ini_len on !up slots -- a stale length
   * here would keep the boot PTO probing a dead slot. */
  c->boot_ini_len = 0;
  /* The closing state ends with the slot (srvrun_close_reap_due must not
   * fire again for a slot already reaped). */
  c->closing = 0;
}

/* 1 if the slot holds anything reclaimable: a live connection, or a boot
 * still reassembling its ClientHello (a stalled one would otherwise pin its
 * table entry forever). */
int srvrun_slot_busy(const srvrun_conn* c) { return c->up || c->boot.any; }

/* RFC 9000 10.1: c's idle period -- the negotiated minimum of both
 * max_idle_timeout values, raised to at least three PTOs. */
u64 srvrun_idle_ms(const srvrun_conn* c) {
  return idle_floor(
      wired_server_idle_timeout_ms(&c->s), srvrun_pto_deadline_ms(c, 0));
}

/* RFC 9000 10.1: the idle timer restarts on every receive and on the first
 * ack-eliciting send after it. */
static u64 srvrun_idle_since(const srvrun_conn* c) {
  return u64_max(c->last_ms, c->idle_tx_ms);
}

/* 1 if c has been idle at least its idle period. */
static int srvrun_idle_due(const srvrun_conn* c, u64 now_ms) {
  return srvrun_slot_busy(c) &&
         now_ms - srvrun_idle_since(c) >= srvrun_idle_ms(c);
}

/* RFC 9000 21.6: 1 if c is a boot (claimed, not yet confirmed) older than
 * SRVRUN_BOOT_DEADLINE_MS -- reaped however fresh its last fragment is. */
int srvrun_boot_overdue(const srvrun_conn* c, u64 now_ms) {
  if (!srvrun_slot_busy(c) || wired_server_is_confirmed(&c->s)) {
    return 0;
  }
  return now_ms - c->boot_claim_ms >= SRVRUN_BOOT_DEADLINE_MS;
}

/* RFC 9000 10.2: 1 once a closing connection's closing period (three PTOs
 * from its CONNECTION_CLOSE, srvrun_close_send) is over. */
int srvrun_close_reap_due(const srvrun_conn* c, u64 now_ms) {
  return c->closing && now_ms >= c->closing_until_ms;
}

int srvrun_reap_due(const srvrun_conn* c, u64 now_ms) {
  return srvrun_idle_due(c, now_ms) || srvrun_boot_overdue(c, now_ms) ||
         srvrun_close_reap_due(c, now_ms);
}
