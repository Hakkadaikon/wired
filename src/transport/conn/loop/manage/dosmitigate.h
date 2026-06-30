#ifndef QUIC_MANAGE_DOSMITIGATE_H
#define QUIC_MANAGE_DOSMITIGATE_H

#include "common/platform/sys/syscall.h"

/* RFC 9308 5.6: a server under load from unverified peers can send a Retry to
 * force address validation, and must never amplify by sending more than three
 * times the bytes received from an unvalidated address. */

/* True if unverified load exceeds the threshold and a Retry should be sent. */
int quic_dos_should_retry(u64 unverified_load, u64 threshold);

/* True if sending `sent` bytes stays within the 3x amplification limit for an
 * address that has sent `received` bytes. */
int quic_dos_amplification_ok(u64 received, u64 sent);

#endif
