#ifndef WIRED_DEBUG_H
#define WIRED_DEBUG_H

#include "common/platform/sys/syscall.h"

/**
 * @file
 * Minimal libc-free tracing for freestanding binaries: write to stderr and
 * format a decimal, with a compile-out gate. The SDK is otherwise silent, so
 * an example/binary that wants trace output uses these rather than pulling in
 * a print library.
 */

/**
 * The value to format and its minimum zero-padded width.
 */
typedef struct {
  u64 v;     /**< value to format as decimal */
  usz width; /**< minimum digit count, at most 20 (a u64's maximum);
                shorter values are zero-padded */
} wired_fmt_u64_in;

/**
 * Write in->v as decimal into out at *at, left-padded with '0' to
 * `in->width`.
 *
 * @param out destination character buffer (caller sizes it; a u64 needs at
 *            most 20 digits)
 * @param at  write cursor into out; advanced past the emitted digits
 * @param in  value and minimum zero-padded width
 */
void wired_fmt_u64(char* out, usz* at, const wired_fmt_u64_in* in);

/**
 * Write a NUL-terminated string to stderr (fd 2).
 *
 * @param s NUL-terminated string to write
 */
void wired_log_str(const char* s);

/**
 * Write a CLOCK_REALTIME "sec.nsec " timestamp then s to stderr.
 *
 * @param s NUL-terminated string written after the timestamp
 */
void wired_log_ts(const char* s);

/**
 * Trace macro: expands to a timestamped log under -DQUIC_DEBUG, nothing else.
 */
#ifdef QUIC_DEBUG
#define WIRED_LOG(s) wired_log_ts(s)
#else
#define WIRED_LOG(s) ((void)0)
#endif

#endif
