#include "app/http3/server/srvloop/srvloop_sent.h"

#include "common/bytes/util/num.h"
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
  return l->ackst.ackd_pn1[i] > lo && l->ackst.ackd_pn1[i] - 1 <= hi;
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

int srvloop_send_onertt_rec(
    wired_srvloop*               l,
    wired_server*                s,
    const wired_srvloop_send_in* in,
    wired_obuf*                  out) {
  srvloop_sent_kind k;
  if (!wired_srvloop_send_onertt(s, in, out)) {
    return 0;
  }
  k = srvloop_sent_classify(in, out->len);
  sentmeta_on_sent(
      &l->ackst.sent, &(sentmeta_out){
                          in->pn, l->now_ms, k.eliciting,
                          pkt_in_flight(k.eliciting, k.padded), out->len});
  srvloop_ackd_note(l, in->pn, k.ack_largest1);
  return 1;
}
