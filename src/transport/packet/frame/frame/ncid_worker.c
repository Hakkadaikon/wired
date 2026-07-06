#include "transport/packet/frame/frame/ncid_worker.h"

/* True if bits/cid_len are usable: bits in [1,8] and at least one byte. */
static int ncid_worker_args_bad(usz cid_len, int bits) {
  return bits < 1 || bits > 8 || cid_len == 0;
}

int quic_ncid_worker_encode(u8* cid, usz cid_len, int bits, u32 worker_idx) {
  if (ncid_worker_args_bad(cid_len, bits)) return -1;
  u8 mask = (u8)(0xFF << (8 - bits));
  cid[0]  = (u8)((cid[0] & ~mask) | ((worker_idx << (8 - bits)) & mask));
  return 0;
}

int quic_ncid_worker_decode(const u8* cid, usz cid_len, int bits) {
  if (ncid_worker_args_bad(cid_len, bits)) return -1;
  u8 mask = (u8)(0xFF << (8 - bits));
  return (cid[0] & mask) >> (8 - bits);
}
