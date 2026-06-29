#include "cvecdsa/cvecdsa.h"
#include "cvecdsa/signed.h"
#include "tls/handshake.h"
#include "tls/ext_algs.h"
#include "hash/sha256.h"
#include "p256sign/sign.h"
#include "ecdsasig/sig_value.h"
#include "util/be.h"

#define QUIC_HS_CERTIFICATE_VERIFY 15

/* Sign the 130-octet content and DER-encode (r, s). der holds up to 72. */
static int cvec_sign(const u8 priv[32], const u8 transcript_hash[32],
                     u8 *der, usz *der_len)
{
    u8 content[130], h[32], r[32], s[32];
    quic_cvecdsa_signed_content(transcript_hash, content);
    quic_sha256(content, 130, h);
    if (!quic_p256sign_sign(priv, h, r, s)) return 0;
    return quic_ecdsasig_encode(r, s, der, 72, der_len);
}

/* Emit header(4) + scheme(2) + sig_len(2) + DER signature. */
static void cvec_emit(u8 *out, const u8 *der, usz der_len, usz *out_len)
{
    usz off = quic_hs_begin(out, der_len + 8, QUIC_HS_CERTIFICATE_VERIFY);
    quic_put_be16(out + off, QUIC_SIG_ECDSA_SECP256R1_SHA256);
    quic_put_be16(out + off + 2, (u16)der_len);
    for (usz i = 0; i < der_len; i++) out[off + 4 + i] = der[i];
    *out_len = off + 4 + der_len;
    quic_hs_finish(out, *out_len);
}

int quic_cvecdsa_build(const u8 priv[32], const u8 transcript_hash[32],
                       u8 *out, usz cap, usz *out_len)
{
    u8 der[72];
    usz der_len = 0;
    if (!cvec_sign(priv, transcript_hash, der, &der_len)) return 0;
    if (cap < der_len + 8) return 0;
    cvec_emit(out, der, der_len, out_len);
    return 1;
}
