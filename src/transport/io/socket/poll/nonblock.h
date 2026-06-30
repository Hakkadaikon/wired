#ifndef QUIC_POLL_NONBLOCK_H
#define QUIC_POLL_NONBLOCK_H

#include "common/platform/sys/syscall.h"

#define QUIC_O_NONBLOCK 0x800 /* O_NONBLOCK */
#define QUIC_F_SETFL    4     /* fcntl cmd F_SETFL */

/* Add O_NONBLOCK to flags (fd-independent, for testing). */
u32 quic_poll_nonblock_flags(u32 flags);

/* fcntl(fd, F_SETFL, O_NONBLOCK). Returns 0 or a negative errno. */
i64 quic_poll_set_nonblock(i64 fd);

#endif
