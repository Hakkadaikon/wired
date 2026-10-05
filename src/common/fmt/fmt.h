#ifndef WIRED_FMT_H
#define WIRED_FMT_H

#include "common/platform/sys/syscall.h"

/**
 * @file
 * libc-free printf-compatible formatter.
 *
 * Conversions: %d %i %u %x %X %p %s %c %% %f; length modifiers hh h l ll z;
 * flags `-` `0` `+` space `#`; width, precision, and `*` for both.
 *
 * Deviations from C99 (deliberate, to stay small):
 *  - %p prints "0x" + lowercase hex, and NULL prints "0x0".
 *  - %s with a NULL pointer prints "(null)" regardless of precision.
 *  - %f rounds half-to-even on the exact binary value (as glibc does).
 *    Magnitudes at or above 2^64 saturate the integer part to
 *    18446744073709551615; precision above 40 is clamped to 40; the
 *    fraction is exact to 2^-60.
 *  - An unknown conversion is copied through verbatim ("%" + the char).
 */

/** Variadic argument list (compiler builtin, not ISA specific). */
typedef __builtin_va_list wired_va_list;

/** Begin reading variadic arguments after `last`. */
#define wired_va_start(ap, last) __builtin_va_start(ap, last)
/** Fetch the next variadic argument as `type`. */
#define wired_va_arg(ap, type) __builtin_va_arg(ap, type)
/** End variadic argument reading. */
#define wired_va_end(ap) __builtin_va_end(ap)

/**
 * Format into out like C99 vsnprintf.
 *
 * @param out destination (may be NULL when cap is 0)
 * @param cap capacity of out in bytes, including the NUL
 * @param fmt printf format string
 * @param ap  arguments
 * @return the length the full output would have (excluding the NUL); output
 *         is truncated and NUL-terminated when this is >= cap
 */
usz wired_vsnprintf(char* out, usz cap, const char* fmt, wired_va_list ap);

/**
 * Format into out like C99 snprintf; see wired_vsnprintf.
 *
 * @param out destination
 * @param cap capacity of out in bytes, including the NUL
 * @param fmt printf format string
 * @return the would-be length, excluding the NUL
 */
usz wired_snprintf(char* out, usz cap, const char* fmt, ...);

/**
 * Format and write to a file descriptor via write(2).
 *
 * The output is formatted into a 512-byte buffer, so anything beyond 511
 * bytes is truncated; short writes are retried.
 *
 * @param fd  file descriptor
 * @param fmt printf format string
 * @return bytes written, or the negative error from write(2)
 */
ssz wired_dprintf(i64 fd, const char* fmt, ...);

#endif
