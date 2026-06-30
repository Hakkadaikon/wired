#ifndef QUIC_UTIL_DBGDUMP_H
#define QUIC_UTIL_DBGDUMP_H

#include "sys/syscall.h"

/* ponytail: temporary stderr hex/decimal dump helpers, used to locate why a
 * decrypted POST request decodes with body_len=0. libc-independent (raw
 * SYS_write to fd 2). Remove once the body-extraction failure is pinned down.
 * Inline so the shared unity TU never re-defines a static across two domains. */

#define QUIC_DBG_DUMP_MAX 512

static inline void quic_dbg_str(const char *s)
{
    usz n = 0;
    while (s[n]) n++;
    syscall3(SYS_write, 2, (i64)s, (i64)n);
}

static inline void quic_dbg_hex(const u8 *d, usz n)
{
    static const char hexd[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    u8 buf[QUIC_DBG_DUMP_MAX * 2];
    usz i, lim = n < QUIC_DBG_DUMP_MAX ? n : QUIC_DBG_DUMP_MAX;
    for (i = 0; i < lim; i++) {
        buf[i * 2] = (u8)hexd[d[i] >> 4];
        buf[i * 2 + 1] = (u8)hexd[d[i] & 0x0f];
    }
    syscall3(SYS_write, 2, (i64)buf, (i64)(lim * 2));
}

static inline void quic_dbg_u64(u64 v)
{
    u8 buf[20];
    usz n = 0;
    do {
        buf[n++] = (u8)('0' + (v % 10));
        v /= 10;
    } while (v);
    while (n) syscall3(SYS_write, 2, (i64)&buf[--n], 1);
}

#endif
