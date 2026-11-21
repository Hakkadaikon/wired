#include "app/http3/server/srvloop/srvloop_impl.h"

static int opened_is_short(const srvloop_opened* o);
static u64 short_pn(
    const wired_srvloop* l, const wired_server* s, wired_mspan p);
static int step_newer_dropped(
    const wired_srvloop* l, const wired_server* s, const srvloop_opened* o);
static int step_admit(
    wired_srvloop* l, wired_server* s, const srvloop_opened* o, wired_span pl);
static u64 step_error(wired_srvloop* l, const srvloop_opened* o, wired_span pl);
static int step_crypto_free(const srvloop_opened* o);
static int step_crypto_ok(
    const wired_srvloop_conn* conn, const srvloop_opened* o, wired_span pl);
static void step_note_close(
    wired_srvloop* l, const srvloop_opened* o, wired_span pl);
static int step_refused(
    wired_srvloop* l, const srvloop_opened* o, wired_span pl);
static int np_above(const wired_srvloop* l);
static int step_np_raises(
    const wired_srvloop* l, const srvloop_opened* o, wired_span pl);
static void step_note_np(
    wired_srvloop* l, const srvloop_opened* o, wired_span pl);
static void step_note_ack(
    wired_srvloop* l, const wired_srvloop_recv_out* ro, u32 kinds);
static void step_frames(
    const wired_srvloop_conn*     conn,
    const wired_srvloop_recv_out* ro,
    const srvloop_opened*         o);

/* A short-header 1-RTT packet (not a long-header 0-RTT one). */
static int opened_is_short(const srvloop_opened* o) {
  return o->level == LEVEL_ONERTT && !srvloop_app_pkt_is_long(o->pkt.p[0]);
}

/* RFC 9000 A.3: a short-header packet's full pn, decoded against the
 * largest received so far without recording it. */
static u64 short_pn(
    const wired_srvloop* l, const wired_server* s, wired_mspan p) {
  return pnum_decode(
      p.p + 1u + s->sdrv.iscid_len, (p.p[0] & 0x03u) + 1u,
      srvloop_app_largest_pn(l));
}

/* RFC 9000 9.6.2: drop_newer is set and o is numbered above everything
 * received so far. */
static int step_newer_dropped(
    const wired_srvloop* l, const wired_server* s, const srvloop_opened* o) {
  return l->drop_newer && opened_is_short(o) &&
         short_pn(l, s, o->pkt) > srvloop_app_largest_pn(l);
}

/* RFC 9000 12.4: an opened packet whose header bits or frames are a
 * connection error latches the code (the first one this step keeps it) and
 * is not processed further. */
static u64 step_error(
    wired_srvloop* l, const srvloop_opened* o, wired_span pl) {
  u64 e = srvloop_payload_error(l, o->level, o->pkt.p[0], pl);
  return e ? e : srvloop_rxacct_kinds(l, pl, o->kinds);
}

static int step_refused(
    wired_srvloop* l, const srvloop_opened* o, wired_span pl) {
  u64 e = step_error(l, o, pl);
  if (!l->transport_error) {
    l->transport_error = e;
  }
  return e != 0;
}

/* 1 iff the opened packet is to be processed: its pn recorded unless it is
 * a discarded newer one, then rejected if a duplicate, which RFC 9000 12.3
 * says to discard after removing protection, or if it is malformed
 * (step_refused). */
static int step_admit(
    wired_srvloop* l, wired_server* s, const srvloop_opened* o, wired_span pl) {
  if (step_newer_dropped(l, s, o)) {
    return 0;
  }
  srvloop_note_app_rx(l, s, o);
  srvloop_note_hs_rx(l, o);
  return !srvloop_step_dup(l, o->level) && !step_refused(l, o, pl);
}

/* The just-recorded application pn is above every earlier non-probing one
 * (compared before np_hi is updated). */
static int np_above(const wired_srvloop* l) {
  return !l->np_seen || l->app_rx_pn > l->np_hi;
}

static int step_np_raises(
    const wired_srvloop* l, const srvloop_opened* o, wired_span pl) {
  (void)pl;
  return o->level == LEVEL_ONERTT && framewalk_kinds_non_probing(o->kinds) &&
         np_above(l);
}

/* RFC 9000 9.3: compare against the largest non-probing pn, then raise it.
 * Only a short-header packet sets step_np_new; a 0-RTT one only raises. */
static void step_note_np(
    wired_srvloop* l, const srvloop_opened* o, wired_span pl) {
  int raised = step_np_raises(l, o, pl);
  if (opened_is_short(o)) {
    l->step_np_new = raised;
  }
  if (!raised) {
    return;
  }
  l->np_hi   = l->app_rx_pn;
  l->np_seen = 1;
}

/* The admitted packet's frames: ACKs, ack-owed bookkeeping, then dispatch
 * -- unless its encryption level may not carry the CRYPTO it holds
 * (wired_server_crypto_level_ok; Initial is never dispatched after boot). */
/* RFC 9000 12.3: each space's ACKs apply to that space's own numbers only.
 * 1-RTT ACKs go to the caller's per-step list (wired_sendsess keys its
 * entries by 1-RTT pn); Handshake ACKs mark the boot flight's packets
 * (hs_acked, RFC 9002 A.7); an Initial opened after boot has no record. */
static void step_acks_none(wired_srvloop* l, wired_span pl) {
  (void)l;
  (void)pl;
}

/* shortcut: an ACK of a Handshake number never sent is recorded, not
 * closed with PROTOCOL_VIOLATION (RFC 9000 13.1 SHOULD); its readers mask
 * with the numbers sent (srvrun_boot_hs_unacked). */
static void step_acks_hs(wired_srvloop* l, wired_span pl) {
  l->hs_acked |= srvloop_acked_bits(pl);
}

/* step_acks indexes its table by level. */
_Static_assert(
    LEVEL_INITIAL == 0 && LEVEL_HANDSHAKE == 1 && LEVEL_ONERTT == 2,
    "step_acks take[] order");

static void step_acks(
    wired_srvloop* l, const srvloop_opened* o, wired_span pl) {
  static void (*const take[])(wired_srvloop*, wired_span) = {
      step_acks_none, step_acks_hs, srvloop_collect_acks};
  if (o->kinds & 1u << FK_ACK) {
    take[o->level](l, pl);
  }
}

/* A 1-RTT packet without CRYPTO: wired_server_crypto_level_ok's walk would
 * find none and pass it. */
static int step_crypto_free(const srvloop_opened* o) {
  return o->level == LEVEL_ONERTT && !(o->kinds & 1u << FK_CRYPTO);
}

static int step_crypto_ok(
    const wired_srvloop_conn* conn, const srvloop_opened* o, wired_span pl) {
  return step_crypto_free(o) ||
         wired_server_crypto_level_ok(conn->s, o->level, pl);
}

/* Record the packet just dispatched for acknowledgement -- unless one of
 * its stray STREAM frames found no room (dispatch_stray.c): that packet is
 * left unacknowledged, so the peer sends it again. */
static void step_note_ack(
    wired_srvloop* l, const wired_srvloop_recv_out* ro, u32 kinds) {
  if (srvloop_stray_ackable(l)) {
    srvloop_step_note_ack_owed(
        l, framewalk_kinds_ack_eliciting(kinds), ro->level);
  }
}

static void step_frames(
    const wired_srvloop_conn*     conn,
    const wired_srvloop_recv_out* ro,
    const srvloop_opened*         o) {
  step_acks(conn->l, o, ro->payload);
  if (step_crypto_ok(conn, o, ro->payload)) {
    srvloop_step_dispatch(conn, ro->payload, o->kinds);
  }
  step_note_ack(conn->l, ro, o->kinds);
}

/* RFC 9000 10.2.2: latch the peer's CONNECTION_CLOSE, when pl has one. */
static void step_note_close(
    wired_srvloop* l, const srvloop_opened* o, wired_span pl) {
  if (o->kinds & 1u << FK_CONNECTION_CLOSE) {
    l->peer_closed |= srvloop_has_close(pl, &l->peer_close_code);
  }
}

/* RFC 9000 13.4.1: an admitted (opened, non-duplicate) application-space
 * packet's ECN codepoint counts toward the cumulative ACK_ECN totals. */
static void step_note_ecn(wired_srvloop* l, int level) {
  if (level == LEVEL_ONERTT) {
    wired_srvloop_ecn_note(l, l->rx_ecn);
  }
}

/* An opened packet: admitted (step_admit), then its frames processed. */
void srvloop_step_opened(
    const wired_srvloop_conn*     conn,
    const wired_srvloop_recv_out* ro,
    wired_mspan                   pkt) {
  wired_srvloop* l = conn->l;
  srvloop_opened o = {ro->level, pkt, framewalk_kinds(ro->payload)};
  if (!step_admit(l, conn->s, &o, ro->payload)) {
    return;
  }
  step_note_ecn(l, o.level);
  step_note_np(l, &o, ro->payload);
  step_note_close(l, &o, ro->payload);
  step_frames(conn, ro, &o);
}
