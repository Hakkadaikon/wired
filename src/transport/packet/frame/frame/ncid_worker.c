#include "transport/packet/frame/frame/ncid_worker.h"

#include "common/platform/rng/rng.h"

/* True if bits/cid_len are usable: bits in [1,8] and at least one byte. */
static int ncid_worker_args_bad(usz cid_len, int bits) {
  return bits < 1 || bits > 8 || cid_len == 0;
}

int ncid_worker_encode(u8* cid, usz cid_len, int bits, u32 worker_idx) {
  if (ncid_worker_args_bad(cid_len, bits)) {
    return -1;
  }
  u8 mask = (u8)(0xFF << (8 - bits));
  cid[0]  = (u8)((cid[0] & ~mask) | ((worker_idx << (8 - bits)) & mask));
  return 0;
}

int ncid_worker_decode(const u8* cid, usz cid_len, int bits) {
  if (ncid_worker_args_bad(cid_len, bits)) {
    return -1;
  }
  u8 mask = (u8)(0xFF << (8 - bits));
  return (cid[0] & mask) >> (8 - bits);
}

int ncid_route_keygen(ncid_route_key* key) {
  if (!rng_bytes((u8*)key->k, sizeof key->k)) {
    return 0;
  }
  key->k[1] |= 1;
  key->k[2] |= 1;
  return 1;
}

u8 ncid_route_mask(const u8* cid, const ncid_route_key* key) {
  u64 w = (u64)cid[1] | ((u64)cid[2] << 8) | ((u64)cid[3] << 16) |
          ((u64)cid[4] << 24);
  u64 x = (w ^ key->k[0]) * key->k[1];
  x ^= x >> 32;
  x *= key->k[2];
  return (u8)(x >> 56);
}

int ncid_route_encode(
    u8* cid, usz cid_len, u8 core, const ncid_route_key* key) {
  if (cid_len < NCID_ROUTE_MIN_LEN) {
    return -1;
  }
  cid[0] = (u8)(core ^ ncid_route_mask(cid, key));
  return 0;
}

u8 ncid_route_decode(const u8* cid, const ncid_route_key* key) {
  return (u8)(cid[0] ^ ncid_route_mask(cid, key));
}
