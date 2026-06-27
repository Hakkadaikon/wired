#ifndef QUIC_RECOVERY_PROBE_H
#define QUIC_RECOVERY_PROBE_H

#include "sys/syscall.h"

/* RFC 9002 6.2.4: on PTO expiry send probe packets to elicit an ACK. */

/* Number of probe packets to send: 2 when the PTO fired, else 0. */
int quic_probe_count(int pto_fired);

/* 1 if a probe should be sent: PTO expired (sender may probe even with no
 * bytes in flight to elicit an ACK). */
int quic_probe_should_send(u64 bytes_in_flight, int pto_expired);

#endif
