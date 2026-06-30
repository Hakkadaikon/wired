#include "tls/ext/salpn/ch_ext.h"

/* RFC 8446 4.1.2. */

static u16 rd16(const u8 *p) { return (u16)((u16)p[0] << 8 | p[1]); }

/* Skip a vector with a 1-byte length prefix at *p (end bound). Returns 1. */
static int salpn_skip_v8(const u8 *m, usz end, usz *p)
{
    usz n;
    if (*p + 1 > end) return 0;
    n = m[*p];
    *p += 1 + n;
    return *p <= end;
}

/* Skip a vector with a 2-byte length prefix at *p (end bound). Returns 1. */
static int salpn_skip_v16(const u8 *m, usz end, usz *p)
{
    usz n;
    if (*p + 2 > end) return 0;
    n = rd16(m + *p);
    *p += 2 + n;
    return *p <= end;
}

/* Advance *p from the body start past the fixed/variable prefix to the
 * extensions length field. Returns 1 if it lands within end. */
static int to_exts(const u8 *m, usz end, usz *p)
{
    *p += 2 + 32;                    /* legacy_version + random */
    if (!salpn_skip_v8(m, end, p)) return 0;    /* session_id */
    if (!salpn_skip_v16(m, end, p)) return 0;   /* cipher_suites */
    return salpn_skip_v8(m, end, p);            /* legacy_compression_methods */
}

/* One extension at *q: -1 overrun, 0 mismatch (advance), 1 match (capture). */
static int one_ext(const u8 *m, usz *q, usz end, u16 ext_type,
                   const u8 **ext_data, usz *ext_len)
{
    usz dlen = rd16(m + *q + 2);
    if (*q + 4 + dlen > end) return -1;
    if (rd16(m + *q) == ext_type) {
        *ext_data = m + *q + 4;
        *ext_len = dlen;
        return 1;
    }
    *q += 4 + dlen;
    return 0;
}

/* Scan the extensions block [q,end) for ext_type. */
static int scan(const u8 *m, usz q, usz end, u16 ext_type,
                const u8 **ext_data, usz *ext_len)
{
    while (q + 4 <= end) {
        int r = one_ext(m, &q, end, ext_type, ext_data, ext_len);
        if (r != 0) return r > 0;
    }
    return 0;
}

/* Read the 2-byte extensions block length at *p and set bounds. */
static int block_end(const u8 *m, usz n, usz p, usz *q, usz *end)
{
    if (p + 2 > n) return 0;
    *end = p + 2 + rd16(m + p);
    *q = p + 2;
    return *end <= n;
}

/* Locate the extensions block end and capture its start in *q. */
static int exts_bounds(const u8 *m, usz n, usz *q, usz *end)
{
    usz p = 4;                       /* msg_type(1) + length(3) */
    if (!to_exts(m, n, &p)) return 0;
    return block_end(m, n, p, q, end);
}

int quic_salpn_find_extension(const u8 *ch_msg, usz ch_len, u16 ext_type,
                              const u8 **ext_data, usz *ext_len)
{
    usz q, end;
    if (!exts_bounds(ch_msg, ch_len, &q, &end)) return 0;
    return scan(ch_msg, q, end, ext_type, ext_data, ext_len);
}
