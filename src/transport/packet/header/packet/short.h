#ifndef QUIC_PACKET_SHORT_H
#define QUIC_PACKET_SHORT_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.3. Build a short header (1-RTT) packet header into buf.
 * byte0 = 0x40 (fixed bit) | spin<<5 | key_phase<<2 | (pn_len-1),
 * then DCID (dcid_len bytes, no length prefix) and the packet number
 * in pn_len big-endian bytes. spin and key_phase are treated as 0/1.
 * pn_len must be 1..4. Returns bytes written, or 0 on bad args / no room. */
usz quic_short_build(u8 *buf, usz cap, const u8 *dcid, u8 dcid_len,
                     u8 spin, u8 key_phase, u64 pn, usz pn_len);

#endif
