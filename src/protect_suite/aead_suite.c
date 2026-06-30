#include "protect_suite/aead_suite.h"
#include "tls/handshake/core/tls/cipher.h"
#include "crypto/symmetric/aead/gcm/gcm.h"
#include "crypto/symmetric/aead/chacha/aead.h"

/* RFC 9001 5.3 nonce: iv with pn XORed into the low 8 bytes. */
static void suite_nonce(const u8 *iv, u64 pn, u8 nonce[12])
{
    for (usz i = 0; i < 12; i++) nonce[i] = iv[i];
    for (usz i = 0; i < 8; i++) nonce[11 - i] ^= (u8)(pn >> (8 * i));
}

static usz gcm_seal(const u8 *key, const u8 nonce[12], const u8 *aad,
                    usz aad_len, const u8 *pt, usz pt_len, u8 *out)
{
    quic_aes128 a;
    quic_aes128_init(&a, key);
    quic_gcm_seal(&a, nonce, aad, aad_len, pt, pt_len, out, out + pt_len);
    return pt_len + QUIC_GCM_TAG;
}

static usz cha_seal(const u8 *key, const u8 nonce[12], const u8 *aad,
                    usz aad_len, const u8 *pt, usz pt_len, u8 *out)
{
    quic_chapoly_seal(key, nonce, aad, aad_len, pt, pt_len, out, out + pt_len);
    return pt_len + QUIC_CHAPOLY_TAG;
}

usz quic_aead_suite_seal(u16 suite, const u8 *key, const u8 *iv, u64 pn,
                         const u8 *aad, usz aad_len,
                         const u8 *pt, usz pt_len, u8 *out)
{
    u8 nonce[12];
    suite_nonce(iv, pn, nonce);
    if (suite == QUIC_TLS_AES_128_GCM_SHA256)
        return gcm_seal(key, nonce, aad, aad_len, pt, pt_len, out);
    if (suite == QUIC_TLS_CHACHA20_POLY1305_SHA256)
        return cha_seal(key, nonce, aad, aad_len, pt, pt_len, out);
    return 0;
}

static usz gcm_open(const u8 *key, const u8 nonce[12], const u8 *aad,
                    usz aad_len, const u8 *ct, usz ct_len, u8 *pt)
{
    quic_aes128 a;
    quic_aes128_init(&a, key);
    if (!quic_gcm_open(&a, nonce, aad, aad_len, ct, ct_len, ct + ct_len, pt))
        return 0;
    return ct_len;
}

static usz cha_open(const u8 *key, const u8 nonce[12], const u8 *aad,
                    usz aad_len, const u8 *ct, usz ct_len, u8 *pt)
{
    if (!quic_chapoly_open(key, nonce, aad, aad_len, ct, ct_len, ct + ct_len, pt))
        return 0;
    return ct_len;
}

usz quic_aead_suite_open(u16 suite, const u8 *key, const u8 *iv, u64 pn,
                         const u8 *aad, usz aad_len,
                         const u8 *ct, usz ct_len, u8 *pt)
{
    u8 nonce[12];
    suite_nonce(iv, pn, nonce);
    if (suite == QUIC_TLS_AES_128_GCM_SHA256)
        return gcm_open(key, nonce, aad, aad_len, ct, ct_len, pt);
    if (suite == QUIC_TLS_CHACHA20_POLY1305_SHA256)
        return cha_open(key, nonce, aad, aad_len, ct, ct_len, pt);
    return 0;
}
