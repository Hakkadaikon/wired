#include "transport/recovery/detect/lossdrive/lossdrive.h"

#include "transport/recovery/rtx/sentpkt/loss_detect.h"

/* True when slot i holds a packet just marked lost. */
static int slot_lost(const sentpkt* t, usz i) {
  return t->e[i].used && t->e[i].state == SP_LOST;
}

/* RFC 9002 6: reclaim slots marked lost so the table no longer tracks them. */
static void drop_lost(sentpkt* t) {
  for (usz i = 0; i < SENTPKT_CAP; i++) {
    if (slot_lost(t, i)) t->e[i].used = 0;
  }
}

void lossdrive_on_ack(sentpkt* state, const lossdrive_in* in, u64out lost) {
  loss_params p = {in->largest_acked, in->now, in->loss_delay};
  loss_detect(state, &p, lost);
  drop_lost(state);
}
