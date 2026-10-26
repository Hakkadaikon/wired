#include "app/http3/server/srvloop/srvloop_sent.h"

#include "transport/packet/frame/frame/dispatch.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/recovery/detect/recovery/inflight.h"

/** The parts of one 1-RTT payload the sent-packet record keeps. */
typedef struct {
  int eliciting; /**< RFC 9002 2: an ack-eliciting frame */
  int padded;    /**< a PADDING frame */
} srvloop_sent_kind;

static void srvloop_sent_frame(srvloop_sent_kind* k, u64 type) {
  frame_kind kind = frame_classify(type);
  k->eliciting |= frame_ack_eliciting(kind);
  k->padded |= kind == FK_PADDING;
}

/* send.c leads a payload shorter than its stateless-reset-proof minimum
 * with PADDING (send_onertt_padded): a sealed packet longer than the short
 * header (byte0 + DCID + 4-byte pn) + payload + 16-byte tag carries some. */
static int srvloop_sent_grew(const wired_srvloop_send_in* in, usz sealed) {
  return sealed > 5u + in->cli_scid.n + in->payload.n + 16u;
}

static srvloop_sent_kind srvloop_sent_classify(
    const wired_srvloop_send_in* in, usz sealed) {
  srvloop_sent_kind k = {0, 0};
  framewalk         it;
  framewalk_item    fr;
  framewalk_init(&it, in->payload.p, in->payload.n);
  while (framewalk_next(&it, &fr)) {
    srvloop_sent_frame(&k, fr.type);
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
      &l->sent, &(sentmeta_out){
                    in->pn, l->now_ms, k.eliciting,
                    pkt_in_flight(k.eliciting, k.padded), out->len});
  return 1;
}
