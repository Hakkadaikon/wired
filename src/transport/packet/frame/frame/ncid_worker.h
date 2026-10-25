#ifndef FRAME_NCID_WORKER_H
#define FRAME_NCID_WORKER_H

#include "common/platform/sys/syscall.h"

/* Soft-affinity hint for multi-worker sharding: pack a worker index into the
 * leading bits of cid[0] so a NAT-rebind or kernel 4-tuple re-hash still has
 * a chance of steering back to the worker that issued the CID. This does not
 * implement steering or migration — pure bit-packing only. */

/* Encode worker_idx into the leading `bits` bits of cid[0] (most-significant
 * bit first within that byte). `bits` must be in [1,8]. Bytes beyond the
 * masked high bits of cid[0] are left untouched.
 *
 * worker_idx is masked silently if it does not fit in `bits` bits: this is a
 * cheap, non-validating bit-packing helper meant for a hot path, not an
 * input-validation boundary.
 *
 * Returns 0 on success, negative if bits is out of range or cid_len==0. */
int ncid_worker_encode(u8* cid, usz cid_len, int bits, u32 worker_idx);

/* Decode the worker index back out of cid[0]'s leading `bits` bits.
 * Returns the decoded index (>=0), or negative if bits is out of range or
 * cid_len==0. */
int ncid_worker_decode(const u8* cid, usz cid_len, int bits);

/** RFC 9312 2.6 / RFC 9000 5.1: a routing byte readable only by holders of a
 * per-process key (the AF_XDP BPF steering program and the server), not by
 * an on-path observer. cid[0] = core ^ mask, where mask is a keyed mix of
 * cid[1..4], so each CID of a connection shows an unrelated first byte.
 * This is obfuscation (QUIC-LB style, no block cipher: the BPF side must
 * stay a short straight-line program), not encryption.
 *
 * The mix, mirrored instruction for instruction by xdpbpf_prog_build:
 *   w = cid[1] | cid[2] << 8 | cid[3] << 16 | cid[4] << 24  (BPF LDXW, LE)
 *   x = (w ^ k[0]) * k[1];  x ^= x >> 32;  x *= k[2];  mask = x >> 56. */
typedef struct {
  /** k[0] xor key, k[1] and k[2] odd multipliers */
  u64 k[3];
} ncid_route_key;

/* Bytes of a CID the routing byte reads (cid[0] plus the 4 mixed in). */
#define NCID_ROUTE_MIN_LEN 5

/* Fill key from the CSPRNG (multipliers forced odd). Returns 1, or 0 if the
 * RNG failed. */
int ncid_route_keygen(ncid_route_key* key);

/* The keyed mask for cid (cid[1..4] must be readable). */
u8 ncid_route_mask(const u8* cid, const ncid_route_key* key);

/* Set cid[0] so ncid_route_decode yields core. Returns 0, or negative if
 * cid_len < NCID_ROUTE_MIN_LEN. */
int ncid_route_encode(u8* cid, usz cid_len, u8 core, const ncid_route_key* key);

/* The routing byte (core) carried by cid; cid_len >= NCID_ROUTE_MIN_LEN. */
u8 ncid_route_decode(const u8* cid, const ncid_route_key* key);

#endif
