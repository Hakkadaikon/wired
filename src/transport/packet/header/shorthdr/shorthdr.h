#ifndef QUIC_SHORTHDR_SHORTHDR_H
#define QUIC_SHORTHDR_SHORTHDR_H

#include "common/bytes/span/span.h"

/* RFC 9000 17.3.1: build a 1-RTT short header. */

/* First byte: 0 1 S R R K P P. Fixed bit set, spin in bit5, key phase in
 * bit2, reserved bits (0x18) clear, pn_len-1 in the low two bits.
 * spin and key_phase are treated as 0/1; pn_len must be 1..4. */
u8 quic_shorthdr_byte0(int spin, int key_phase, u8 pn_len);

/* One short header: DCID (written without a length prefix), the spin and
 * key-phase bits, and the packet number as pn_len big-endian bytes. */
typedef struct {
  int       spin;
  int       key_phase;
  quic_span dcid;
  u64       pn;
  u8        pn_len;
} quic_shorthdr_desc;

/* Build byte0, DCID and pn into out; total length to out->len. Returns 1 on
 * success, 0 on bad args (pn_len not 1..4) or insufficient room. */
int quic_shorthdr_build(const quic_shorthdr_desc* d, quic_obuf* out);

#endif
