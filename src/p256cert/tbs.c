#include "p256cert/tbs.h"
#include "p256cert/spki.h"
#include "p256cert/enc.h"
#include "asn1/der.h"

/* RFC 5758 3.2. ecdsa-with-SHA256 OID 1.2.840.10045.4.3.2. */
static const u8 oid_ecdsa_sha256[] = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02};
/* RFC 5280 A.1. id-at-commonName OID 2.5.4.3. */
static const u8 pc_oid_cn[] = {0x55, 0x04, 0x03};
/* RFC 5280 4.1.2.5.1. Fixed validity window as UTCTime YYMMDDHHMMSSZ. */
static const u8 pc_not_before[] = "200101000000Z";
static const u8 pc_not_after[]  = "300101000000Z";
static const u8 pc_cn_value[] = "localhost";

usz quic_p256cert_sigalg(u8 *out, usz cap)
{
    u8 inner[16];
    quic_p256cert_enc e = {inner, sizeof(inner), 0, 1};
    quic_p256cert_put(&e, QUIC_DER_OID, oid_ecdsa_sha256,
                      sizeof(oid_ecdsa_sha256));
    return quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out, cap);
}

/* RFC 5280 4.1.2.4. AttributeTypeAndValue SEQUENCE{ id-at-commonName, value }. */
static usz pc_build_atv(u8 *out, usz cap)
{
    u8 inner[64];
    quic_p256cert_enc e = {inner, sizeof(inner), 0, 1};
    quic_p256cert_put(&e, QUIC_DER_OID, pc_oid_cn, sizeof(pc_oid_cn));
    quic_p256cert_put(&e, 0x0c, pc_cn_value, sizeof(pc_cn_value) - 1); /* UTF8String */
    return quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out, cap);
}

/* RFC 5280 4.1.2.4. Name SEQUENCE{ SET{ SEQUENCE{ id-at-commonName, value }}}. */
static usz pc_build_name(u8 *out, usz cap)
{
    u8 atv[64], rdn[80];
    quic_p256cert_enc er = quic_p256cert_loaded(atv, pc_build_atv(atv,
                                                              sizeof(atv)));
    quic_p256cert_enc es = quic_p256cert_loaded(rdn, quic_p256cert_wrap(&er,
                              QUIC_DER_SET, rdn, sizeof(rdn)));
    return quic_p256cert_wrap(&es, QUIC_DER_SEQUENCE, out, cap);
}

/* RFC 5280 4.1.2.5. Validity SEQUENCE { notBefore UTCTime, notAfter UTCTime }. */
static usz pc_build_validity(u8 *out, usz cap)
{
    u8 v[48];
    quic_p256cert_enc e = {v, sizeof(v), 0, 1};
    quic_p256cert_put(&e, 0x17, pc_not_before, sizeof(pc_not_before) - 1); /* UTCTime */
    quic_p256cert_put(&e, 0x17, pc_not_after, sizeof(pc_not_after) - 1);
    return quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out, cap);
}

/* RFC 5280 4.1. Emit version, serial, signature AlgID, issuer onto e. */
static void tbs_head(quic_p256cert_enc *e, const u8 *name, usz nn)
{
    static const u8 version[] = {0xa0, 0x03, 0x02, 0x01, 0x02}; /* [0] v3 */
    static const u8 serial[]  = {0x02, 0x01, 0x01};            /* INTEGER 1 */
    u8 alg[16];
    quic_p256cert_put_pre(e, version, sizeof(version));
    quic_p256cert_put_pre(e, serial, sizeof(serial));
    quic_p256cert_put_pre(e, alg, quic_p256cert_sigalg(alg, sizeof(alg)));
    quic_p256cert_put_pre(e, name, nn);
}

int quic_p256cert_tbs(const u8 x[32], const u8 y[32], u8 *out, usz cap,
                      usz *out_len)
{
    u8 name[80], val[48], spki[128], body[512];
    usz nn = pc_build_name(name, sizeof(name)), sn = 0;
    quic_p256cert_enc e = {body, sizeof(body), 0, 1};
    quic_p256cert_spki(x, y, spki, sizeof(spki), &sn);
    tbs_head(&e, name, nn);
    quic_p256cert_put_pre(&e, val, pc_build_validity(val, sizeof(val)));
    quic_p256cert_put_pre(&e, name, nn);                       /* subject */
    quic_p256cert_put_pre(&e, spki, sn);
    *out_len = quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out, cap);
    return *out_len != 0;
}
