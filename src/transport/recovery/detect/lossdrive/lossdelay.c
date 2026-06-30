#include "transport/recovery/detect/lossdrive/lossdelay.h"

#include "common/bytes/util/num.h"
#include "transport/recovery/detect/recovery/lossdetect.h"

u64 quic_lossdrive_loss_delay(
    u64 smoothed_rtt, u64 latest_rtt, u64 granularity) {
  u64 rtt       = quic_u64_max(smoothed_rtt, latest_rtt);
  u64 threshold = rtt * QUIC_LOSS_TIME_NUM / QUIC_LOSS_TIME_DEN;
  return quic_u64_max(threshold, granularity);
}
