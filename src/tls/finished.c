#include "tls/finished.h"
#include "hash/hmac.h"

void quic_tls_finished_verify_data(const u8 base_key[QUIC_HKDF_PRK],
                                   const u8 transcript_hash[QUIC_SHA256_DIGEST],
                                   u8 out[QUIC_TLS_VERIFY_DATA])
{
    u8 finished_key[QUIC_SHA256_DIGEST];
    quic_hkdf_expand_label(base_key, "finished", 8, 0, 0,
                           finished_key, QUIC_SHA256_DIGEST);
    quic_hmac_sha256(finished_key, QUIC_SHA256_DIGEST,
                     transcript_hash, QUIC_SHA256_DIGEST, out);
}

/* Constant-time 32-byte digest comparison: 0 if equal. */
static u8 digest_diff(const u8 a[32], const u8 b[32])
{
    u8 d = 0;
    for (usz i = 0; i < 32; i++) d |= a[i] ^ b[i];
    return d;
}

int quic_tls_finished_check(const u8 base_key[QUIC_HKDF_PRK],
                            const u8 transcript_hash[QUIC_SHA256_DIGEST],
                            const u8 received[QUIC_TLS_VERIFY_DATA])
{
    u8 want[QUIC_TLS_VERIFY_DATA];
    quic_tls_finished_verify_data(base_key, transcript_hash, want);
    return digest_diff(want, received) == 0;
}
