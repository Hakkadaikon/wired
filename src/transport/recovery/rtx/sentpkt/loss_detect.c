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
static int inflight(const quic_sentpkt *t, usz i) {
  return t->e[i].used && t->e[i].state == QUIC_SP_INFLIGHT;
}

/* True when an in-flight packet has crossed either threshold. */
static int past_threshold(
    const quic_sentpkt_entry *p, u64 largest_acked, u64 now, u64 loss_delay) {
  return by_packet(largest_acked, p->pn) ||
         by_time(now, p->time_sent, loss_delay);
}

/* An in-flight packet past either threshold is lost. */
static int loss_is_lost(
    const quic_sentpkt *t, usz i, u64 largest_acked, u64 now, u64 loss_delay) {
  return inflight(t, i) &&
         past_threshold(&t->e[i], largest_acked, now, loss_delay);
}

void quic_loss_detect(
    quic_sentpkt *t,
    u64           largest_acked,
    u64           now,
    u64           loss_delay,
    u64          *lost_pns,
    usz          *n_lost) {
  *n_lost = 0;
  for (usz i = 0; i < QUIC_SENTPKT_CAP; i++) {
    if (!loss_is_lost(t, i, largest_acked, now, loss_delay)) continue;
    t->e[i].state         = QUIC_SP_LOST;
    lost_pns[(*n_lost)++] = t->e[i].pn;
  }
}
