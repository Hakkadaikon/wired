#include "rsa/mgf1.h"
#include "hash/sha256.h"
#include "util/be.h"

/* SHA-256(seed || counter_be32) -> 32-byte block. */
static void mgf1_block(const u8 *seed, usz seed_len, u32 counter, u8 out[32])
{
    u8 c[4];
    quic_put_be32(c, counter);
    quic_sha256_ctx s;
    quic_sha256_init(&s);
    quic_sha256_update(&s, seed, seed_len);
    quic_sha256_update(&s, c, 4);
    quic_sha256_final(&s, out);
}

static usz min_usz(usz a, usz b)
{
    return a < b ? a : b;
}

/* RFC 8017 B.2.1. */
void quic_mgf1_sha256(const u8 *seed, usz seed_len, u8 *mask, usz mask_len)
{
    u8 t[32];
    usz off = 0;
    for (u32 counter = 0; off < mask_len; counter++) {
        mgf1_block(seed, seed_len, counter, t);
        usz n = min_usz(mask_len - off, 32);
        for (usz i = 0; i < n; i++) mask[off + i] = t[i];
        off += n;
    }
}
