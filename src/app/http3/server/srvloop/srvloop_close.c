#include "app/http3/server/srvloop/srvloop_impl.h"

static int  srvloop_close_type(u64 type);
static void srvloop_push_ack(wired_srvloop* l, u64 lo, u64 hi);
static int  srvloop_ecn_newer(const wired_srvloop* l, const ack_frame* f);
static void srvloop_note_ecn(wired_srvloop* l, const ack_frame* f);
static void srvloop_take_ack(wired_srvloop* l, const u8* buf, usz n);

/* RFC 9000 19.19: 1 if type is either CONNECTION_CLOSE variant. */
static int srvloop_close_type(u64 type) {
  return type == FRAME_CONN_CLOSE_TPT || type == FRAME_CONN_CLOSE_APP;
}

/* RFC 9000 10.2.2: 1 if the opened payload carries a CONNECTION_CLOSE frame
 * (either variant, any encryption level — the peer is closing or draining). */
int srvloop_has_close(wired_span pl) {
  framewalk      it;
  framewalk_item fr;
  framewalk_init(&it, pl.p, pl.n);
  while (framewalk_next(&it, &fr)) {
    if (srvloop_close_type(fr.type)) {
      return 1;
    }
  }
  return 0;
}

/* Record one ACK range on l's per-step list; overflow is dropped. */
static void srvloop_push_ack(wired_srvloop* l, u64 lo, u64 hi) {
  if (l->ack_n >= sizeof l->ack_lo / sizeof l->ack_lo[0]) {
    return;
  }
  l->ack_lo[l->ack_n] = lo;
  l->ack_hi[l->ack_n] = hi;
  l->ack_n++;
}

/* 1 if f's ECN counts should replace the step's latched ones: a type-0x03
 * ACK, and none latched yet or f acknowledges at least as large a packet
 * number (RFC 9000 13.4.2.1 -- a reordered older ACK carries smaller
 * cumulative counts and must not be mistaken for a regression). */
static int srvloop_ecn_newer(const wired_srvloop* l, const ack_frame* f) {
  return f->has_ecn &&
         (!l->ecn_ack_seen || f->ranges[0].hi >= l->ecn_ack_largest);
}

/* Latch a type-0x03 ACK's ECN counts for the caller's per-step ECN
 * validation (RFC 9000 13.4.2) -- counts are cumulative, largest wins. */
static void srvloop_note_ecn(wired_srvloop* l, const ack_frame* f) {
  if (!srvloop_ecn_newer(l, f)) {
    return;
  }
  l->ecn_ack_seen    = 1;
  l->ecn_ack_largest = f->ranges[0].hi;
  l->ecn_ack_ect0    = f->ect0;
  l->ecn_ack_ect1    = f->ect1;
  l->ecn_ack_ce      = f->ce;
}

/* Decode one ACK frame and record its ranges (RFC 9000 19.3). */
static void srvloop_take_ack(wired_srvloop* l, const u8* buf, usz n) {
  ack_frame f;
  if (ack_decode(buf, n, &f) == 0) {
    return;
  }
  for (usz i = 0; i < f.n_ranges; i++) {
    srvloop_push_ack(l, f.ranges[i].lo, f.ranges[i].hi);
  }
  srvloop_note_ecn(l, &f);
}

/* Surface every ACK frame in the opened payload to the caller's per-step
 * list (RFC 9000 19.3) — the caller consumes them to advance its own sent
 * bookkeeping (e.g. a multi-packet response in flight). */
void srvloop_collect_acks(wired_srvloop* l, wired_span pl) {
  framewalk      it;
  framewalk_item fr;
  framewalk_init(&it, pl.p, pl.n);
  while (framewalk_next(&it, &fr)) {
    if (frame_classify(fr.type) == FK_ACK) {
      srvloop_take_ack(l, fr.start, fr.remaining);
    }
  }
}

/* RFC 9000 13.2.1/13.2.2: an ack-eliciting packet in this pn space records
 * pn into its receive window (dedup + reordering-tolerant) and raises the
 * pending count that decides whether/when an ACK is owed. A non-eliciting
 * packet (e.g. ACK-only) touches neither -- receiving only ACKs is never
 * itself a reason to ACK. */
void srvloop_note_ack_owed(
    pnspaces_recv* recv,
    int            space,
    ackpolicy*     policy,
    wired_span     pl,
    u64            pn,
    u64            now_ms) {
  if (!framewalk_ack_eliciting(pl)) {
    return;
  }
  pnspaces_on_recv(recv, space, pn);
  ackpolicy_on_eliciting(policy, now_ms);
}
