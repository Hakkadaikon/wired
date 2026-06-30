#include "transport/recovery/rtx/sentmeta/detect_loss.h"

/* RFC 9002 6.1.1: pn is kPacketThreshold or more below largest_acked. */
static int sentmeta_by_packet(u64 largest_acked, u64 pn) {
  return largest_acked >= pn + QUIC_SENTMETA_PACKET_THRESHOLD;
}

/* RFC 9002 6.1.2: sent at or before now - loss_delay. */
static int sentmeta_by_time(u64 now, u64 sent, u64 loss_delay) {
  return now >= sent + loss_delay;
}

/* A tracked packet past either threshold is lost. */
static int sentmeta_is_lost(
    const quic_sentmeta_pkt *p, u64 largest_acked, u64 now, u64 loss_delay) {
  return sentmeta_by_packet(largest_acked, p->pn) ||
         sentmeta_by_time(now, p->time_sent, loss_delay);
}

static int sentmeta_lost_slot(
    const quic_sentmeta *m, usz i, u64 largest_acked, u64 now, u64 loss_delay) {
  return m->pkts[i].used &&
         sentmeta_is_lost(&m->pkts[i], largest_acked, now, loss_delay);
}

void quic_sentmeta_detect_loss(
    quic_sentmeta *m,
    u64            largest_acked,
    u64            now,
    u64            loss_delay,
    u64           *lost_pns,
    usz           *n_lost) {
  *n_lost = 0;
  for (usz i = 0; i < QUIC_SENTMETA_CAP; i++) {
    if (!sentmeta_lost_slot(m, i, largest_acked, now, loss_delay)) continue;
    lost_pns[(*n_lost)++] = m->pkts[i].pn;
    quic_sentmeta_reclaim(m, i);
  }
}
