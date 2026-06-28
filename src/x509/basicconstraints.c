#include "x509/basicconstraints.h"
#include "asn1/der.h"
#include "asn1/derseq.h"
#include "asn1/derval.h"

/* RFC 5280 4.1.2.1. version is [0] EXPLICIT, optional and default v1. */
#define X509_VERSION_TAG 0xa0
/* RFC 5280 4.1.2.9. extensions is [3] EXPLICIT. */
#define X509_EXTENSIONS_TAG 0xa3
/* RFC 5280 4.1. tbs elements before extensions (version excluded):
 * serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo. */
#define EXT_SKIP 6

/* X.690 8.2. BOOLEAN universal tag. */
#define QUIC_DER_BOOLEAN 0x01

/* id-ce-basicConstraints = 2.5.29.19 */
static const u8 oid_bc[] = {0x55, 0x1d, 0x13};

/* The tbs SEQUENCE value (after its own header). 0 if not a SEQUENCE. */
static int bc_tbs_value(const u8 *tbs, usz tbs_len, const u8 **v, usz *vlen)
{
    u8 tag;
    usz used;
    if (!quic_der_read(tbs, tbs_len, &tag, v, vlen, &used)) return 0;
    return tag == QUIC_DER_SEQUENCE;
}

/* Drop the optional version element. */
static int bc_skip_version(quic_derseq *c)
{
    u8 tag;
    const u8 *val;
    usz vlen;
    if (c->off < c->len && c->p[c->off] == X509_VERSION_TAG)
        return quic_derseq_next(c, &tag, &val, &vlen);
    return 1;
}

/* Advance the cursor past n elements. 1 if all were present. */
static int bc_skip_n(quic_derseq *c, usz n)
{
    u8 tag;
    const u8 *val;
    usz vlen;
    for (usz i = 0; i < n; i++)
        if (!quic_derseq_next(c, &tag, &val, &vlen)) return 0;
    return 1;
}

/* Position the cursor before the extensions [3] element. */
static int bc_at_extensions(const u8 *tbs, usz tbs_len, quic_derseq *c)
{
    const u8 *v;
    usz vlen;
    if (!bc_tbs_value(tbs, tbs_len, &v, &vlen)) return 0;
    quic_derseq_init(c, v, vlen);
    return bc_skip_version(c) && bc_skip_n(c, EXT_SKIP);
}

/* The SEQUENCE value wrapped directly inside the given bytes. */
static int bc_unwrap_seq(const u8 *val, usz vlen, const u8 **seq, usz *slen)
{
    u8 tag;
    usz used;
    if (!quic_der_read(val, vlen, &tag, seq, slen, &used)) return 0;
    return tag == QUIC_DER_SEQUENCE;
}

/* The [3] explicit tag wrapping the extensions, read from cursor c. */
static int bc_next_is_ext_tag(quic_derseq *c, const u8 **val, usz *vlen)
{
    u8 tag;
    return quic_derseq_next(c, &tag, val, vlen) && tag == X509_EXTENSIONS_TAG;
}

/* RFC 5280 4.1.2.9. Reach the extensions SEQUENCE value inside [3]. */
static int bc_reach_extensions(const u8 *tbs, usz tbs_len, const u8 **ext, usz *elen)
{
    quic_derseq c;
    const u8 *val;
    usz vlen;
    if (!bc_at_extensions(tbs, tbs_len, &c)) return 0;
    if (!bc_next_is_ext_tag(&c, &val, &vlen)) return 0;
    return bc_unwrap_seq(val, vlen, ext, elen);
}

/* RFC 5280 4.1.2.9. extnID of one Extension equals the wanted OID. */
static int bc_ext_id_is(const u8 *e, usz e_len, const u8 *oid, usz oid_len)
{
    quic_derseq f;
    u8 tag;
    const u8 *id;
    usz id_len;
    quic_derseq_init(&f, e, e_len);
    if (!quic_derseq_next(&f, &tag, &id, &id_len)) return 0;
    return tag == QUIC_DER_OID && quic_der_oid_equal(id, id_len, oid, oid_len);
}

/* RFC 5280 4.1.2.9. The extnValue OCTET STRING (last element of an Extension,
 * after extnID and the optional critical BOOLEAN). */
static int bc_ext_value(const u8 *e, usz e_len, const u8 **val, usz *val_len)
{
    quic_derseq f;
    u8 tag;
    const u8 *o;
    usz o_len;
    quic_derseq_init(&f, e, e_len);
    while (quic_derseq_next(&f, &tag, &o, &o_len))
        if (tag == QUIC_DER_OCTET_STRING) { *val = o; *val_len = o_len; return 1; }
    return 0;
}

/* RFC 5280 4.1.2.9. Find the extnValue OCTET STRING of the wanted OID. */
static int bc_find_ext(const u8 *ext, usz elen, const u8 *oid, usz oid_len,
                    const u8 **val, usz *val_len)
{
    quic_derseq exts;
    u8 tag;
    const u8 *e;
    usz e_len;
    quic_derseq_init(&exts, ext, elen);
    while (quic_derseq_next(&exts, &tag, &e, &e_len))
        if (bc_ext_id_is(e, e_len, oid, oid_len))
            return bc_ext_value(e, e_len, val, val_len);
    return 0;
}

/* X.690 11.1. A DER BOOLEAN encoding TRUE (single non-zero octet). */
static int bc_is_true_boolean(u8 tag, const u8 *b, usz b_len)
{
    return tag == QUIC_DER_BOOLEAN && b_len == 1 && b[0] != 0x00;
}

/* RFC 5280 4.2.1.9. cA is the optional leading BOOLEAN of the SEQUENCE. */
static int bc_ca_true(const u8 *val, usz val_len)
{
    quic_derseq c;
    u8 tag;
    const u8 *bc, *b;
    usz bc_len, b_len;
    if (!bc_unwrap_seq(val, val_len, &bc, &bc_len)) return 0;
    quic_derseq_init(&c, bc, bc_len);
    if (!quic_derseq_next(&c, &tag, &b, &b_len)) return 0;
    return bc_is_true_boolean(tag, b, b_len);
}

int quic_x509_is_ca(const u8 *tbs, usz tbs_len)
{
    const u8 *ext, *val;
    usz elen, val_len;
    if (!bc_reach_extensions(tbs, tbs_len, &ext, &elen)) return 0;
    if (!bc_find_ext(ext, elen, oid_bc, sizeof(oid_bc), &val, &val_len)) return 0;
    return bc_ca_true(val, val_len);
}
