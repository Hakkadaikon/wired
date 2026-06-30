#include "common/platform/rng/cidgen.h"

#include "common/platform/rng/rng.h"

/* RFC 9000 5.1: connection IDs are 1..20 bytes. */
int quic_cid_len_valid(u8 len) { return len >= 1 && len <= 20; }

int quic_cid_generate(u8 *cid, u8 len) {
  if (!quic_cid_len_valid(len)) return 0;
  return quic_rng_bytes(cid, len);
}
