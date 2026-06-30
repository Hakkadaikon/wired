#ifndef QUIC_POLL_WAIT_H
#define QUIC_POLL_WAIT_H

#include "common/platform/sys/syscall.h"

#define QUIC_POLLIN 0x001 /* POLLIN: data to read */

/* struct pollfd as the kernel expects it (events/revents are short). */
typedef struct {
    i32 fd;
    u16 events;
    u16 revents;
} quic_pollfd;

/* Fill a pollfd for read-readiness on fd (fd-independent, for testing). */
void quic_poll_fill_readable(quic_pollfd *p, i64 fd);

/* Wait until fd is readable or timeout_ms elapses (poll syscall).
 * Returns 1 if readable, 0 on timeout, negative errno on error. */
i64 quic_poll_wait_readable(i64 fd, u64 timeout_ms);

#endif
