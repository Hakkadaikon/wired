#ifndef WIRED_ARCH_TYPES_H
#define WIRED_ARCH_TYPES_H

/**
 * @file
 * The SDK's fixed-width integer types (LP64 data model).
 *
 * With no libc there is no <stdint.h>, so every other header builds on the
 * typedefs here. The widths assume an LP64 ABI (long is 64-bit), which holds
 * for every architecture this SDK targets (x86_64 Linux today).
 */

typedef unsigned long  u64; /**< unsigned 64-bit integer */
typedef long           i64; /**< signed 64-bit integer */
typedef unsigned int   u32; /**< unsigned 32-bit integer */
typedef int            i32; /**< signed 32-bit integer */
typedef unsigned short u16; /**< unsigned 16-bit integer */
typedef unsigned char  u8;  /**< unsigned 8-bit integer / byte */
typedef i64            ssz; /**< signed size (ssize_t equivalent) */
typedef u64            usz; /**< unsigned size (size_t equivalent) */

#endif
