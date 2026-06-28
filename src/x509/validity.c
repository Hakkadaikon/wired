#include "x509/validity.h"
#include "asn1/der.h"
#include "asn1/derseq.h"

/* RFC 5280 4.1.2.1 / 4.1. version is [0] EXPLICIT; before validity sit
 * serialNumber, signature and issuer. */
#define VAL_VERSION_TAG 0xa0
#define VALIDITY_SKIP 3

#define DER_UTCTIME 0x17
#define DER_GENTIME 0x18

static int is_digit(u8 c) { return c >= '0' && c <= '9'; }

/* Parse n ASCII digits into a number. 1 ok, 0 if any octet is not a digit. */
static int digits(const u8 *p, usz n, u64 *out)
{
    u64 v = 0;
    for (usz i = 0; i < n; i++) {
        if (!is_digit(p[i])) return 0;
        v = v * 10 + (u64)(p[i] - '0');
    }
    *out = v;
    return 1;
}

/* Z-terminated string of the expected length. */
static int zterm(const u8 *v, usz len, usz want) { return len == want && v[want - 1] == 'Z'; }

/* RFC 5280 4.1.2.5.1. Century for a 2-digit year: <50 => 2000s, else 1900s. */
static u64 century(u64 yy) { return yy < 50 ? 2000 : 1900; }

/* UTCTime YYMMDDHHMMSS digits into a full YYYYMMDDHHMMSS. */
static int utc_digits(const u8 *v, u64 *out)
{
    u64 yy, rest;
    if (!digits(v, 2, &yy)) return 0;
    if (!digits(v + 2, 10, &rest)) return 0;
    *out = (yy + century(yy)) * 10000000000ULL + rest;
    return 1;
}

/* RFC 5280 4.1.2.5.1. UTCTime is YYMMDDHHMMSSZ. */
static int utctime(const u8 *v, usz len, u64 *out)
{
    if (!zterm(v, len, 13)) return 0;
    return utc_digits(v, out);
}

/* RFC 5280 4.1.2.5.2. GeneralizedTime is YYYYMMDDHHMMSSZ. */
static int gentime(const u8 *v, usz len, u64 *out)
{
    if (!zterm(v, len, 15)) return 0;
    return digits(v, 14, out);
}

/* Decode a Time (UTCTime or GeneralizedTime) into YYYYMMDDHHMMSS. */
static int time_value(u8 tag, const u8 *v, usz len, u64 *out)
{
    if (tag == DER_UTCTIME) return utctime(v, len, out);
    if (tag == DER_GENTIME) return gentime(v, len, out);
    return 0;
}

/* Drop the optional version element. */
static int val_skip_version(quic_derseq *c)
{
    u8 tag;
    const u8 *val;
    usz vlen;
    if (c->off < c->len && c->p[c->off] == VAL_VERSION_TAG)
        return quic_derseq_next(c, &tag, &val, &vlen);
    return 1;
}

/* Advance past n elements. 1 if all present. */
static int val_skip_n(quic_derseq *c, usz n)
{
    u8 tag;
    const u8 *val;
    usz vlen;
    for (usz i = 0; i < n; i++)
        if (!quic_derseq_next(c, &tag, &val, &vlen)) return 0;
    return 1;
}

/* The tbs SEQUENCE value (after its own header). 0 if not a SEQUENCE. */
static int val_tbs_value(const u8 *tbs, usz tbs_len, const u8 **v, usz *vlen)
{
    u8 tag;
    usz used;
    if (!quic_der_read(tbs, tbs_len, &tag, v, vlen, &used)) return 0;
    return tag == QUIC_DER_SEQUENCE;
}

/* Position c before the validity element, inside the tbs SEQUENCE value. */
static int tbs_to_validity(const u8 *tbs, usz tbs_len, quic_derseq *c)
{
    const u8 *v;
    usz vlen;
    if (!val_tbs_value(tbs, tbs_len, &v, &vlen)) return 0;
    quic_derseq_init(c, v, vlen);
    return val_skip_version(c) && val_skip_n(c, VALIDITY_SKIP);
}

/* Read one Time element of c into *out. */
static int next_time(quic_derseq *c, u64 *out)
{
    u8 tag;
    const u8 *v;
    usz vlen;
    if (!quic_derseq_next(c, &tag, &v, &vlen)) return 0;
    return time_value(tag, v, vlen, out);
}

/* RFC 5280 4.1.2.5. Extract notBefore and notAfter from the Validity value. */
static int validity_bounds(const u8 *val, usz vlen, u64 *nb, u64 *na)
{
    quic_derseq c;
    quic_derseq_init(&c, val, vlen);
    return next_time(&c, nb) && next_time(&c, na);
}

/* The Validity SEQUENCE value out of tbs. */
static int reach_validity(const u8 *tbs, usz tbs_len, const u8 **v, usz *vlen)
{
    quic_derseq c;
    u8 tag;
    if (!tbs_to_validity(tbs, tbs_len, &c)) return 0;
    if (!quic_derseq_next(&c, &tag, v, vlen)) return 0;
    return tag == QUIC_DER_SEQUENCE;
}

/* notBefore <= now <= notAfter. */
static int in_window(u64 nb, u64 na, u64 now) { return nb <= now && now <= na; }

int quic_x509_validity_ok(const u8 *tbs, usz tbs_len, u64 now)
{
    const u8 *v;
    usz vlen;
    u64 nb, na;
    if (!reach_validity(tbs, tbs_len, &v, &vlen)) return 0;
    return validity_bounds(v, vlen, &nb, &na) && in_window(nb, na, now);
}
