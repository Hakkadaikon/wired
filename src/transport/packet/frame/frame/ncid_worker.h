#ifndef QUIC_FRAME_NCID_WORKER_H
#define QUIC_FRAME_NCID_WORKER_H

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
int quic_ncid_worker_encode(u8* cid, usz cid_len, int bits, u32 worker_idx);

/* Decode the worker index back out of cid[0]'s leading `bits` bits.
 * Returns the decoded index (>=0), or negative if bits is out of range or
 * cid_len==0. */
int quic_ncid_worker_decode(const u8* cid, usz cid_len, int bits);

#endif
