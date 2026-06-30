#include "transport/conn/loop/manage/dosmitigate.h"

/* RFC 9308 5.6 */
int quic_dos_should_retry(u64 unverified_load, u64 threshold) {
  return unverified_load > threshold;
}

/* RFC 9308 5.6 */
int quic_dos_amplification_ok(u64 received, u64 sent) {
  return sent <= 3 * received;
}
