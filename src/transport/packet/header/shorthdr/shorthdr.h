#ifndef QUIC_SHORTHDR_SHORTHDR_H
#define QUIC_SHORTHDR_SHORTHDR_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.3.1: build a 1-RTT short header. */

/* First byte: 0 1 S R R K P P. Fixed bit set, spin in bit5, key phase in
 * bit2, reserved bits (0x18) clear, pn_len-1 in the low two bits.
 * spin and key_phase are treated as 0/1; pn_len must be 1..4. */
u8 quic_shorthdr_byte0(int spin, int key_phase, u8 pn_len);

/* Build byte0, then DCID (no length prefix) and pn as pn_len big-endian
 * bytes into out (cap bytes); total length to *out_len. Returns 1 on
 * success, 0 on bad args (pn_len not 1..4) or insufficient room. */
int quic_shorthdr_build(int spin, int key_phase, const u8 *dcid, u8 dcid_len,
                        u64 pn, u8 pn_len, u8 *out, usz cap, usz *out_len);

#endif
