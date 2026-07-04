#include "transport/recovery/rtx/sentpkt/loss_detect.h"

/* RFC 9002 6.1.1: pn is kPacketThreshold or more below largest_acked. */
static int by_packet(u64 largest_acked, u64 pn) {
  return largest_acked >= pn + QUIC_SENTPKT_PACKET_THRESHOLD;
}

/* RFC 9002 6.1.2: sent at or before now - loss_delay. */
static int by_time(u64 now, u64 sent, u64 loss_delay) {
  return now >= sent + loss_delay;
}

/* True when slot i is a tracked in-flight packet. */
static int inflight(const quic_sentpkt* t, usz i) {
  return t->e[i].used && t->e[i].state == QUIC_SP_INFLIGHT;
}

/* True when an in-flight packet has crossed either threshold. */
static int past_threshold(
    const quic_sentpkt_entry* p, const quic_loss_params* lp) {
  return by_packet(lp->largest_acked, p->pn) ||
         by_time(lp->now, p->time_sent, lp->loss_delay);
}

/* An in-flight packet past either threshold is lost. */
static int loss_is_lost(
    const quic_sentpkt* t, usz i, const quic_loss_params* lp) {
  return inflight(t, i) && past_threshold(&t->e[i], lp);
}

void quic_loss_detect(
    quic_sentpkt* t, const quic_loss_params* p, quic_u64out lost) {
  *lost.n = 0;
  for (usz i = 0; i < QUIC_SENTPKT_CAP; i++) {
    if (!loss_is_lost(t, i, p)) continue;
    t->e[i].state         = QUIC_SP_LOST;
    lost.out[(*lost.n)++] = t->e[i].pn;
  }
}
