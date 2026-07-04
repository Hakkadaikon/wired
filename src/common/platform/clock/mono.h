#ifndef QUIC_CLOCK_MONO_H
#define QUIC_CLOCK_MONO_H

#include "common/platform/sys/syscall.h"

/** @file
 * Monotonic elapsed-time clock (CLOCK_MONOTONIC), for measuring intervals
 * such as connection idle age (RFC 9000 10.1). Unlike quic_clock_ymdhms's
 * wall clock it never jumps backward on system time changes. */

/** Milliseconds from the kernel's monotonic clock.
 * @return elapsed ms since an arbitrary fixed origin, or 0 on failure. */
u64 quic_clock_mono_ms(void);

#endif
