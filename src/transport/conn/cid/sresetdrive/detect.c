#include "transport/conn/cid/sresetdrive/detect.h"

#include "common/bytes/util/ct.h"

/* RFC 9000 10.3.1 */
int quic_sresetdrive_is_reset(
    const u8 *packet, usz len, const u8 *expected_token) {
  if (len < QUIC_SRESETDRIVE_MIN) return 0;
  return quic_ct_diff16(
             packet + len - QUIC_SRESETDRIVE_TOKEN, expected_token) == 0;
}
