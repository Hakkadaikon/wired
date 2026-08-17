#include "transport/recovery/detect/lossdrive/lossdelay.h"

#include "common/bytes/util/num.h"
#include "transport/recovery/detect/recovery/lossdetect.h"

u64 lossdrive_loss_delay(u64 smoothed_rtt, u64 latest_rtt, u64 granularity) {
  u64 rtt       = u64_max(smoothed_rtt, latest_rtt);
  u64 threshold = rtt * QUIC_LOSS_TIME_NUM / QUIC_LOSS_TIME_DEN;
  return u64_max(threshold, granularity);
}
