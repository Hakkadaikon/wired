#ifndef QUIC_POLL_DEADLINE_H
#define QUIC_POLL_DEADLINE_H

#include "common/platform/sys/syscall.h"

/* Timer-to-timeout helpers for the connection loop (no syscalls). */

/* Milliseconds to wait until deadline: deadline-now, or 0 if already past. */
u64 quic_poll_timeout_until(u64 now, u64 deadline);

/* Smallest deadline among n entries. Returns 0 if n == 0. */
u64 quic_poll_min_deadline(const u64 *deadlines, usz n);

#endif
