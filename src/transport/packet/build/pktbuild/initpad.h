#ifndef QUIC_PKTBUILD_INITPAD_H
#define QUIC_PKTBUILD_INITPAD_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 14.1: pad a datagram carrying an Initial up to the 1200-byte
 * minimum using PADDING frames (0x00). Writes zero bytes at datagram[current_len..]
 * when current_len < 1200 and the cap allows. Returns the resulting length
 * (>= current_len), or current_len unchanged if already >= 1200 or cap < 1200. */
usz quic_pktbuild_init_pad(u8 *datagram, usz current_len, usz cap);

#endif
