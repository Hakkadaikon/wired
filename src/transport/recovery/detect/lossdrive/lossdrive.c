#include "transport/recovery/detect/lossdrive/lossdrive.h"

#include "transport/recovery/rtx/sentpkt/loss_detect.h"

/* True when slot i holds a packet just marked lost. */
static int slot_lost(const quic_sentpkt *t, usz i) {
  return t->e[i].used && t->e[i].state == QUIC_SP_LOST;
}

/* RFC 9002 6: reclaim slots marked lost so the table no longer tracks them. */
static void drop_lost(quic_sentpkt *t) {
  for (usz i = 0; i < QUIC_SENTPKT_CAP; i++) {
    if (slot_lost(t, i)) t->e[i].used = 0;
  }
}

void quic_lossdrive_on_ack(
    quic_sentpkt *state,
    u64           largest_acked,
    u64           now,
    u64           loss_delay,
    u64          *lost_pns,
    usz          *n_lost) {
  quic_loss_detect(state, largest_acked, now, loss_delay, lost_pns, n_lost);
  drop_lost(state);
}
