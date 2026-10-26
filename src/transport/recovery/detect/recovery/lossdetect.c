#include "transport/recovery/detect/recovery/lossdetect.h"

int loss_by_packet(u64 largest_acked, u64 pn) {
  return largest_acked >= pn + LOSS_PACKET_THRESHOLD;
}
