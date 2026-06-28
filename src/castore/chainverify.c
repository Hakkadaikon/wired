#include "castore/chainverify.h"
#include "x509/x509.h"
#include "x509/spki.h"
#include "x509/rsa_pubkey.h"
#include "x509/ec_pubkey.h"
#include "asn1/der.h"
#include "asn1/derseq.h"
#include "hash/sha256.h"
#include "rsa/rsa_verify.h"
#include "p256/ecdsa_verify.h"

/* View issuer_cert's subjectPublicKey BIT STRING value and its algorithm OID. */
static int issuer_key(const u8 *issuer_cert, usz issuer_len,
                      const u8 **alg, usz *alg_len,
                      const u8 **key, usz *key_len)
{
    quic_x509 c;
    if (!quic_x509_parse(issuer_cert, issuer_len, &c)) return 0;
    return quic_x509_public_key(c.tbs, c.tbs_len, alg, alg_len, key, key_len);
}

/* RFC 5280 6.1.3. SHA-256 of cert's tbsCertificate (the signed bytes). */
static int tbs_hash(const u8 *cert, usz cert_len, u8 hash[32])
{
    quic_x509 c;
    if (!quic_x509_parse(cert, cert_len, &c)) return 0;
    quic_sha256(c.tbs, c.tbs_len, hash);
    return 1;
}

/* RFC 5280 4.1.1.3. View cert's signatureValue, dropping the BIT STRING's
 * leading unused-bits octet (0x00 for whole-octet signatures). */
static int cert_sig(const u8 *cert, usz cert_len, const u8 **sig, usz *sig_len)
{
    quic_x509 c;
    if (!quic_x509_parse(cert, cert_len, &c)) return 0;
    if (c.sig_len < 1) return 0;
    *sig = c.sig + 1;
    *sig_len = c.sig_len - 1;
    return 1;
}

/* SEC1 C.5. Strip one INTEGER sign pad. */
static void chv_strip_pad(const u8 **v, usz *len)
{
    if (*len > 1 && (*v)[0] == 0x00) { (*v)++; (*len)--; }
}

static void chv_left_pad32(u8 out[32], const u8 *v, usz len)
{
    for (usz i = 0; i < 32; i++) out[i] = 0;
    for (usz i = 0; i < len; i++) out[32 - len + i] = v[i];
}

/* A stripped INTEGER value that fits a P-256 scalar. */
static int fits_scalar(usz len) { return len >= 1 && len <= 32; }

/* Read the next element of c, requiring INTEGER. */
static int chv_next_int(quic_derseq *c, const u8 **v, usz *len)
{
    u8 tag;
    if (!quic_derseq_next(c, &tag, v, len)) return 0;
    return tag == QUIC_DER_INTEGER;
}

/* Copy one INTEGER element of c into a 32-byte big-endian field. */
static int chv_copy_int32(quic_derseq *c, u8 out[32])
{
    const u8 *v;
    usz len;
    if (!chv_next_int(c, &v, &len)) return 0;
    chv_strip_pad(&v, &len);
    if (!fits_scalar(len)) return 0;
    chv_left_pad32(out, v, len);
    return 1;
}

/* View an outer SEQUENCE value. */
static int chv_read_seq(const u8 *buf, usz n, const u8 **val, usz *vlen)
{
    u8 tag;
    usz used;
    if (!quic_der_read(buf, n, &tag, val, vlen, &used)) return 0;
    return tag == QUIC_DER_SEQUENCE;
}

/* SEC1 C.5. ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }. */
static int chv_ecdsa_split(const u8 *sig, usz sig_len, u8 r[32], u8 s[32])
{
    const u8 *seq;
    usz seq_len;
    quic_derseq c;
    if (!chv_read_seq(sig, sig_len, &seq, &seq_len)) return 0;
    quic_derseq_init(&c, seq, seq_len);
    if (!chv_copy_int32(&c, r)) return 0;
    return chv_copy_int32(&c, s);
}

static int chv_verify_ecdsa(const u8 *key, usz key_len, const u8 *sig,
                        usz sig_len, const u8 hash[32])
{
    u8 x[32], y[32], r[32], s[32];
    if (!quic_x509_ec_pubkey(key, key_len, x, y)) return 0;
    if (!chv_ecdsa_split(sig, sig_len, r, s)) return 0;
    return quic_ecdsa_p256_verify(x, y, r, s, hash);
}

static int chv_verify_rsa(const u8 *key, usz key_len, const u8 *sig,
                      usz sig_len, const u8 hash[32])
{
    const u8 *n, *e;
    usz n_len, e_len;
    if (!quic_x509_rsa_pubkey(key, key_len, &n, &n_len, &e, &e_len)) return 0;
    return quic_rsa_pkcs1_verify(n, n_len, sig, sig_len, hash, 32);
}

/* RFC 5280 6.1.3. Dispatch on the issuer key type. */
static int verify_by_key(const u8 *alg, usz alg_len, const u8 *key,
                         usz key_len, const u8 *sig, usz sig_len,
                         const u8 hash[32])
{
    if (quic_x509_is_ec(alg, alg_len))
        return chv_verify_ecdsa(key, key_len, sig, sig_len, hash);
    if (quic_x509_is_rsa(alg, alg_len))
        return chv_verify_rsa(key, key_len, sig, sig_len, hash);
    return 0;
}

/* The signed bytes of cert: its tbs hash and its raw signature. */
static int cert_signed(const u8 *cert, usz cert_len, u8 hash[32],
                       const u8 **sig, usz *sig_len)
{
    if (!tbs_hash(cert, cert_len, hash)) return 0;
    return cert_sig(cert, cert_len, sig, sig_len);
}

int quic_castore_verify_signed_by(const u8 *cert, usz cert_len,
                                  const u8 *issuer_cert, usz issuer_len)
{
    const u8 *alg, *key, *sig;
    usz alg_len, key_len, sig_len;
    u8 hash[32];
    if (!issuer_key(issuer_cert, issuer_len, &alg, &alg_len, &key, &key_len))
        return 0;
    if (!cert_signed(cert, cert_len, hash, &sig, &sig_len)) return 0;
    return verify_by_key(alg, alg_len, key, key_len, sig, sig_len, hash);
}
