#ifndef RECOVERY_PROBE_H
#define RECOVERY_PROBE_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 6.2.4: on PTO expiry send probe packets to elicit an ACK. */

/* Number of probe packets to send: 2 when the PTO fired, else 0. */
int probe_count(int pto_fired);

#endif
