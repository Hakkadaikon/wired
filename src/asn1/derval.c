#include "asn1/derval.h"

/* Byte-equal over n octets. */
static int der_bytes_eq(const u8 *a, const u8 *b, usz n)
{
    for (usz i = 0; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

int quic_der_oid_equal(const u8 *oid, usz oid_len,
                       const u8 *expected, usz exp_len)
{
    if (oid_len != exp_len) return 0;
    return der_bytes_eq(oid, expected, oid_len);
}

/* X.690 8.3.2. A leading 0x00 is a pad only when more octets follow. */
static int der_has_pad(const u8 *val, usz val_len)
{
    return val_len > 1 && val[0] == 0x00;
}

/* Empty or negative (top bit of the first octet set, X.690 8.3.2 two's
 * complement) integers have no unsigned magnitude. */
static int der_int_bad(const u8 *val, usz val_len)
{
    return val_len == 0 || (val[0] & 0x80);
}

/* Point p at the unsigned magnitude of nlen octets. 1 if usable, else 0. */
static int der_int_mag(const u8 *val, usz val_len, const u8 **p, usz *nlen)
{
    if (der_int_bad(val, val_len)) return 0;
    usz pad = der_has_pad(val, val_len) ? 1 : 0;
    *p = val + pad;
    *nlen = val_len - pad;
    return 1;
}

/* Big-endian accumulate; nlen must be <= 8. */
static u64 der_be(const u8 *p, usz nlen)
{
    u64 v = 0;
    for (usz i = 0; i < nlen; i++) v = (v << 8) | p[i];
    return v;
}

int quic_der_uint(const u8 *val, usz val_len, u64 *out)
{
    const u8 *p;
    usz nlen;
    if (!der_int_mag(val, val_len, &p, &nlen)) return 0;
    if (nlen > 8) return 0;
    *out = der_be(p, nlen);
    return 1;
}
