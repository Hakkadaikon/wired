#include "transport/packet/frame/frame/crypto_offset.h"

/* RFC 9000 19.6 */
int quic_crypto_offset_ok(u64 offset, u64 len, u64 max_offset) {
  if (offset + len < offset) return 0; /* wrap */
  return offset + len <= max_offset;
}

/* RFC 9000 7.5 */
int quic_crypto_contiguous(u64 received_upto, u64 new_offset) {
  return new_offset <= received_upto;
}
