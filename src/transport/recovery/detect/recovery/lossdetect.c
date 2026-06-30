#include "transport/recovery/detect/recovery/lossdetect.h"

#include "common/bytes/util/num.h"

int quic_loss_by_packet(u64 largest_acked, u64 pn) {
  return largest_acked >= pn + QUIC_LOSS_PACKET_THRESHOLD;
}

/* RFC 9002 6.1.2: 9/8 * max(srtt, latest_rtt). */
static u64 time_threshold(u64 srtt, u64 latest_rtt) {
  u64 rtt = quic_u64_max(srtt, latest_rtt);
  return rtt * QUIC_LOSS_TIME_NUM / QUIC_LOSS_TIME_DEN;
}

int quic_loss_by_time(u64 now, u64 sent_time, u64 srtt, u64 latest_rtt) {
  u64 elapsed = (now > sent_time) ? now - sent_time : 0;
  return elapsed >= time_threshold(srtt, latest_rtt);
}
