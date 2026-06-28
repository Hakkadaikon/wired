#include "selfcert/selfcert.h"
#include "selfcert/tbs.h"
#include "selfcert/derenc.h"
#include "asn1/der.h"
#include "ed25519/ed25519.h"
#include "util/bytes.h"

/* RFC 8410 3. id-Ed25519 OID 1.3.101.112. */
static const u8 oid_ed25519_sig[] = {0x2b, 0x65, 0x70};

/* RFC 5280 4.1.1.2. signatureAlgorithm SEQUENCE { id-Ed25519 } (no params). */
static usz build_sigalg(u8 *out, usz cap)
{
    u8 oid[16];
    usz n;
    if (!quic_selfcert_der_tlv(QUIC_DER_OID, oid_ed25519_sig,
                               sizeof(oid_ed25519_sig), oid, sizeof(oid), &n))
        return 0;
    if (!quic_selfcert_der_tlv(QUIC_DER_SEQUENCE, oid, n, out, cap, &n))
        return 0;
    return n;
}

/* RFC 5280 4.1.1.3. signatureValue BIT STRING (0x00 unused bits || sig). */
static usz build_sigval(const u8 sig[64], u8 *out, usz cap)
{
    u8 bits[65];
    usz n, off = 1;
    bits[0] = 0x00;
    quic_put_bytes(bits, sizeof(bits), &off, sig, 64);
    if (!quic_selfcert_der_tlv(QUIC_DER_BIT_STRING, bits, off, out, cap, &n))
        return 0;
    return n;
}

typedef struct { const u8 *p; usz n; } slice;

/* Concatenate the parts and wrap in the Certificate SEQUENCE. */
static int assemble(const slice *parts, usz cnt, u8 *out, usz cap, usz *out_len)
{
    u8 body[768];
    usz off = 0;
    int ok = 1;
    for (usz i = 0; i < cnt; i++)
        ok &= quic_put_bytes(body, sizeof(body), &off, parts[i].p, parts[i].n);
    return ok && quic_selfcert_der_tlv(QUIC_DER_SEQUENCE, body, off,
                                       out, cap, out_len);
}

/* Derive the public key and sign the freshly built TBS. 0 on any failure. */
static int sign_tbs(const u8 seed[32], u8 *tbs, usz cap, usz *tn, u8 sig[64])
{
    u8 pub[32];
    if (!quic_ed25519_keypair(seed, pub)) return 0;
    if (!quic_selfcert_tbs(pub, tbs, cap, tn)) return 0;
    return quic_ed25519_sign(seed, tbs, *tn, sig);
}

/* True if all three lengths are non-zero (every element encoded). */
static int parts_ok(const slice *p) { return p[0].n && p[1].n && p[2].n; }

int quic_selfcert_build(const u8 seed[32], u8 *cert_out, usz cap, usz *cert_len)
{
    u8 sig[64], tbs[512], alg[16], sv[80];
    usz tn, an = build_sigalg(alg, sizeof(alg)), sn;
    if (!sign_tbs(seed, tbs, sizeof(tbs), &tn, sig)) return 0;
    sn = build_sigval(sig, sv, sizeof(sv));
    slice parts[] = {{tbs, tn}, {alg, an}, {sv, sn}};
    if (!parts_ok(parts)) return 0;
    return assemble(parts, 3, cert_out, cap, cert_len);
}
