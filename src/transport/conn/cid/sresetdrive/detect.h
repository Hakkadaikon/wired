#ifndef QUIC_SRESETDRIVE_DETECT_H
#define QUIC_SRESETDRIVE_DETECT_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.3.1 detecting a stateless reset. A packet that fails to
 * decrypt is checked against the expected Stateless Reset Token: its trailing
 * 16 bytes are compared in constant time. The shortest packet that can carry
 * a reset is 21 bytes (5-byte minimum header room plus the 16-byte token). */

#define QUIC_SRESETDRIVE_TOKEN 16
#define QUIC_SRESETDRIVE_MIN   21

/* 1 if the packet's trailing token matches `expected_token` in constant time
 * and the packet is at least the 21-byte minimum; 0 otherwise. */
int quic_sresetdrive_is_reset(const u8 *packet, usz len,
                              const u8 *expected_token);

#endif
