#ifndef QUIC_HP_HPAPPLY_H
#define QUIC_HP_HPAPPLY_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.4.1: protect byte0's low bits with mask[0] (low 4 bits for long
 * headers, low 5 bits for short headers). XOR is self-inverse, so the same
 * call removes protection. */
u8 quic_hp_protect_byte0(u8 byte0, u8 mask0, int is_long);

/* RFC 9001 5.4.1: protect the packet-number bytes with mask[1..pn_len]. */
void quic_hp_protect_pn(u8 *pn, usz pn_len, const u8 *mask);

#endif
