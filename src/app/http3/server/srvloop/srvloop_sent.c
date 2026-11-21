#include "app/http3/server/srvloop/srvloop_sent.h"

#include "common/bytes/util/num.h"
#include "common/platform/rng/rng.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/dispatch.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/recovery/detect/recovery/inflight.h"

/** The parts of one 1-RTT payload the sent-packet record keeps. */
typedef struct {
  int eliciting;    /**< RFC 9002 2: an ack-eliciting frame */
  int padded;       /**< a PADDING frame */
  u64 ack_largest1; /**< 1 + an ACK frame's Largest Acknowledged, 0 none */
} srvloop_sent_kind;

/* 1 + the Largest Acknowledged of the ACK frame at fr (0 if malformed). */
static u64 srvloop_sent_ack_largest1(const framewalk_item* fr) {
  ack_frame f;
  if (!ack_decode(fr->start, fr->remaining, &f)) {
    return 0;
  }
  return f.ranges[0].hi + 1;
}

static void srvloop_sent_frame(srvloop_sent_kind* k, const framewalk_item* fr) {
  frame_kind kind = frame_classify(fr->type);
  k->eliciting |= frame_ack_eliciting(kind);
  k->padded |= kind == FK_PADDING;
  if (kind == FK_ACK) {
    k->ack_largest1 = srvloop_sent_ack_largest1(fr);
  }
}

/* Remember pn as carrying an ACK whose Largest Acknowledged is
 * ack_largest1 - 1 (no-op when ack_largest1 is 0). */
static void srvloop_ackd_note(wired_srvloop* l, u64 pn, u64 ack_largest1) {
  if (!ack_largest1) {
    return;
  }
  l->ackst.ackd_pn1[l->ackst.ackd_next]     = pn + 1;
  l->ackst.ackd_largest[l->ackst.ackd_next] = ack_largest1 - 1;
  l->ackst.ackd_next = (u8)((l->ackst.ackd_next + 1) % WIRED_SRVLOOP_ACKD);
}

/* 1 if remembered slot i's packet lies in [lo, hi]. */
static int srvloop_ackd_hit(const wired_srvloop* l, usz i, u64 lo, u64 hi) {
  return u64_pn1_in(l->ackst.ackd_pn1[i], lo, hi);
}

void srvloop_ackd_on_acked(wired_srvloop* l, u64 lo, u64 hi) {
  for (usz i = 0; i < WIRED_SRVLOOP_ACKD; i++) {
    if (srvloop_ackd_hit(l, i, lo, hi)) {
      l->ackst.floor1 = u64_max(l->ackst.floor1, l->ackst.ackd_largest[i] + 1);
      l->ackst.ackd_pn1[i] = 0;
    }
  }
}

/* send.c leads a payload shorter than its stateless-reset-proof minimum
 * with PADDING (send_onertt_padded): a sealed packet longer than the short
 * header (byte0 + DCID + 4-byte pn) + payload + 16-byte tag carries some. */
static int srvloop_sent_grew(const wired_srvloop_send_in* in, usz sealed) {
  return sealed > 5u + in->cli_scid.n + in->payload.n + 16u;
}

static srvloop_sent_kind srvloop_sent_classify(
    const wired_srvloop_send_in* in, usz sealed) {
  srvloop_sent_kind k = {0, 0, 0};
  framewalk         it;
  framewalk_item    fr;
  framewalk_init(&it, in->payload.p, in->payload.n);
  while (framewalk_next(&it, &fr)) {
    srvloop_sent_frame(&k, &fr);
  }
  k.padded |= srvloop_sent_grew(in, sealed);
  return k;
}

/* RFC 9000 10.1: the first ack-eliciting send since the last receive
 * restarts the idle timer (a later one does not). */
static void srvloop_sent_idle(srvloop_ackst* a, u64 now_ms) {
  if (!a->idle_tx_ms) {
    a->idle_tx_ms = now_ms;
  }
}

/* RFC 9002 A.8: an ack-eliciting send restarts the 1-RTT PTO
 * (last_elicit_ms) and uses up one probe allowance (probe_n); RFC 9000
 * 10.1: and maybe the idle timer. */
static void srvloop_sent_elicit(wired_srvloop* l, int eliciting) {
  if (!eliciting) {
    return;
  }
  srvloop_sent_idle(&l->ackst, l->now_ms);
  l->ackst.last_elicit_ms = l->now_ms;
  l->ackst.probe_n        = (u8)(l->ackst.probe_n ? l->ackst.probe_n - 1 : 0);
}

/* Test-only override forcing the skip RNG to fail (getrandom failing is
 * not practically triggerable from a test). The test harness entries
 * (tests/run.c main, build/shards/shard_main.c) turn it on at startup so a
 * unit run never skips at a random position; skip tests turn it off for
 * their own scope. Production never sets it (0: the real RNG). */
static int g_srvloop_pn_skip_rng_fail;

void srvloop_test_force_pn_skip_rng_fail(int v) {
  g_srvloop_pn_skip_rng_fail = v;
}

/* Test-only pin for the arm's draw bytes (pinned wins over the force-fail
 * flag); on = 0 restores the real RNG. Reset after the owning test. */
static int g_srvloop_pn_skip_rng_pinned;
static u8  g_srvloop_pn_skip_rng_pin[2];

__attribute__((unused)) static void srvloop_test_pin_pn_skip_rng(
    int on, u8 b0, u8 b1) {
  g_srvloop_pn_skip_rng_pinned = on;
  g_srvloop_pn_skip_rng_pin[0] = b0;
  g_srvloop_pn_skip_rng_pin[1] = b1;
}

static int srvloop_pn_skip_rng(u8 r[2]) {
  if (g_srvloop_pn_skip_rng_pinned) {
    r[0] = g_srvloop_pn_skip_rng_pin[0];
    r[1] = g_srvloop_pn_skip_rng_pin[1];
    return 1;
  }
  return !g_srvloop_pn_skip_rng_fail && rng_bytes(r, 2);
}

/* RFC 9000 21.4: place the next skip 1..WIRED_SRVLOOP_PN_GAP_MAX numbers
 * (9 random bits + 1) past the next unsent number (tx_pn). Armed right
 * after a skip of S (tx_pn = S + 1), that puts the next skipped number
 * uniformly in S+2..S+513: every number past S+1 has a nonzero chance of
 * being the skipped one, so a peer gets no window it could ACK
 * optimistically with zero risk. A geometric draw would make the
 * per-packet hazard constant (memoryless), but needs a draw per packet or
 * log arithmetic; the uniform draw costs one fixed-size read per skip and
 * bounds the worst-case interval, so detection latency is bounded too. A
 * failed RNG read leaves the skip unarmed (no skip; sending never blocks)
 * and the next send retries. */
static void srvloop_pn_skip_arm(wired_srvloop* l) {
  u8 r[2];
  if (!srvloop_pn_skip_rng(r)) {
    return;
  }
  l->pn_skip_at = l->tx_pn + 1 + (((u64)(r[1] & 1) << 8) | r[0]);
}

/* RFC 9000 21.4: skip the next 1-RTT packet number (tx_pn, not yet used)
 * and remember it -- a peer acknowledging it claims receipt of a packet
 * never sent, the optimistic-ACK tripwire srvloop_validate.c checks. The
 * ring overwrite drops the oldest number, which merely stops being
 * checked. Re-arming here lets the next skip fire as early as two numbers
 * later; the number right after a skipped one always exists, but two
 * consecutive skips would be indistinguishable from one to the validator
 * anyway. */
static void srvloop_pn_skip(wired_srvloop* l) {
  l->pn_skipped1[l->pn_skip_next] = l->tx_pn + 1;
  l->pn_skip_next = (u8)((l->pn_skip_next + 1) % WIRED_SRVLOOP_PN_SKIPS);
  l->tx_pn++;
  l->pn_skip_at = 0; /* on an RNG failure the next send retries the arm */
  srvloop_pn_skip_arm(l);
}

/* Arm, or fire, the packet-number skip after a recorded 1-RTT send. */
static void srvloop_pn_skip_maybe(wired_srvloop* l) {
  if (!l->pn_skip_at) {
    srvloop_pn_skip_arm(l);
    return;
  }
  if (l->tx_pn >= l->pn_skip_at) {
    srvloop_pn_skip(l);
  }
}

int srvloop_send_onertt_rec(
    wired_srvloop*               l,
    wired_server*                s,
    const wired_srvloop_send_in* in,
    wired_obuf*                  out) {
  srvloop_sent_kind k;
  if (!wired_srvloop_send_onertt(s, in, out)) {
    /* shortcut: a pn consumed by a failed seal stays unsent and is not in
     * the skip ring, so an ACK of it passes; upgrade if seal failures ever
     * become reachable from peer input. */
    return 0;
  }
  k = srvloop_sent_classify(in, out->len);
  sentmeta_on_sent(
      &l->ackst.sent, &(sentmeta_out){
                          in->pn, l->now_ms, k.eliciting,
                          pkt_in_flight(k.eliciting, k.padded), out->len});
  srvloop_ackd_note(l, in->pn, k.ack_largest1);
  srvloop_sent_elicit(l, k.eliciting);
  srvloop_pn_skip_maybe(l);
  return 1;
}

/* The bits of [lo, hi] below 32. */
static u32 srvloop_range_bits(u64 lo, u64 hi) {
  u64 top = u64_min(hi, 31);
  if (lo > top) {
    return 0;
  }
  return (u32)(((2ull << top) - 1) & ~((1ull << lo) - 1));
}

/* RFC 9000 19.3.1: every range of the ACK frame at fr, as bits. */
static u32 srvloop_ack_bits(const framewalk_item* fr) {
  ack_frame f;
  u32       bits = 0;
  if (!ack_decode(fr->start, fr->remaining, &f)) {
    return 0;
  }
  for (usz i = 0; i < f.n_ranges; i++) {
    bits |= srvloop_range_bits(f.ranges[i].lo, f.ranges[i].hi);
  }
  return bits;
}

u32 srvloop_acked_bits(wired_span pl) {
  framewalk      it;
  framewalk_item fr;
  u32            bits = 0;
  framewalk_init(&it, pl.p, pl.n);
  while (framewalk_next(&it, &fr)) {
    if (frame_classify(fr.type) == FK_ACK) {
      bits |= srvloop_ack_bits(&fr);
    }
  }
  return bits;
}
