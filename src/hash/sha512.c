#include "hash/sha512.h"

/* FIPS 180-4 4.2.3 round constants. */
static const u64 S512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static const u64 S512_H0[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

#define S512ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S512BS0(x) (S512ROR(x, 28) ^ S512ROR(x, 34) ^ S512ROR(x, 39))
#define S512BS1(x) (S512ROR(x, 14) ^ S512ROR(x, 18) ^ S512ROR(x, 41))
#define S512SS0(x) (S512ROR(x, 1) ^ S512ROR(x, 8) ^ ((x) >> 7))
#define S512SS1(x) (S512ROR(x, 19) ^ S512ROR(x, 61) ^ ((x) >> 6))

void quic_sha512_init(quic_sha512_ctx *s)
{
    for (usz i = 0; i < 8; i++) s->h[i] = S512_H0[i];
    s->total = 0;
    s->buf_len = 0;
}

/* Load one 64-bit big-endian word at byte offset o. */
static u64 load_be64(const u8 *p, usz o)
{
    u64 v = 0;
    for (usz j = 0; j < 8; j++) v = (v << 8) | p[o + j];
    return v;
}

/* Build the 80-word message sha512_schedule from one 128-byte block. */
static void sha512_schedule(const u8 *p, u64 w[80])
{
    for (usz i = 0; i < 16; i++) w[i] = load_be64(p, i * 8);
    for (usz i = 16; i < 80; i++)
        w[i] = S512SS1(w[i - 2]) + w[i - 7] + S512SS0(w[i - 15]) + w[i - 16];
}

/* One round: mix the working vector v[0..7] with sha512_schedule word kw. */
static void sha512_round_step(u64 v[8], u64 kw)
{
    u64 t1 = v[7] + S512BS1(v[4]) + CH(v[4], v[5], v[6]) + kw;
    u64 t2 = S512BS0(v[0]) + MAJ(v[0], v[1], v[2]);
    for (usz j = 7; j > 0; j--) v[j] = v[j - 1]; /* shift e..a down */
    v[4] += t1;        /* e += t1 (after shift, v[4] holds old d) */
    v[0] = t1 + t2;    /* a = t1 + t2 */
}

/* Run all 80 rounds over the working vector seeded from the hash state. */
static void sha512_run_rounds(const u64 *h, const u64 w[80], u64 v[8])
{
    for (usz i = 0; i < 8; i++) v[i] = h[i];
    for (usz i = 0; i < 80; i++) sha512_round_step(v, S512_K[i] + w[i]);
}

static void sha512_compress(quic_sha512_ctx *s, const u8 *p)
{
    u64 w[80];
    u64 v[8];
    sha512_schedule(p, w);
    sha512_run_rounds(s->h, w, v);
    for (usz i = 0; i < 8; i++) s->h[i] += v[i];
}

/* Absorb whole 128-byte blocks straight from data; returns bytes consumed. */
static usz sha512_absorb_blocks(quic_sha512_ctx *s, const u8 *data, usz len)
{
    usz off = 0;
    while (len - off >= QUIC_SHA512_BLOCK) {
        sha512_compress(s, data + off);
        off += QUIC_SHA512_BLOCK;
    }
    return off;
}

/* Append n bytes (n < block, no overflow) into the pending sha512_buffer. */
static void sha512_buffer(quic_sha512_ctx *s, const u8 *data, usz n)
{
    for (usz i = 0; i < n; i++) s->buf[s->buf_len + i] = data[i];
    s->buf_len += n;
}

/* Bytes to pull from data to complete a pending partial block, or 0 if
 * there is no partial block or not enough data to fill it. */
static usz sha512_pending_take(const quic_sha512_ctx *s, usz len)
{
    usz want = QUIC_SHA512_BLOCK - s->buf_len;
    return (s->buf_len != 0 && len >= want) ? want : 0;
}

/* If a partial block is pending, top it up from data and flush when full.
 * Returns the number of bytes consumed from data. */
static usz sha512_fill_pending(quic_sha512_ctx *s, const u8 *data, usz len)
{
    usz take = sha512_pending_take(s, len);
    sha512_buffer(s, data, take);
    if (take != 0) { sha512_compress(s, s->buf); s->buf_len = 0; }
    return take;
}

void quic_sha512_update(quic_sha512_ctx *s, const u8 *data, usz len)
{
    usz off = sha512_fill_pending(s, data, len);
    off += sha512_absorb_blocks(s, data + off, len - off);
    sha512_buffer(s, data + off, len - off);
    s->total += len;
}

/* Append 0x80 then zero bytes until exactly 112 bytes sit in the block,
 * leaving room for the 16-byte length (FIPS 180-4 5.1.2). */
static void sha512_pad_message(quic_sha512_ctx *s)
{
    u8 b = 0x80;
    quic_sha512_update(s, &b, 1);
    b = 0;
    while (s->buf_len != 112) quic_sha512_update(s, &b, 1);
}

/* Write the 128-bit message length: high 64 bits are always zero here. */
static void put_len(u8 lenbe[16], u64 bits)
{
    for (usz i = 0; i < 8; i++) lenbe[i] = 0;
    for (usz i = 0; i < 8; i++) lenbe[8 + i] = (u8)(bits >> (56 - i * 8));
}

/* Store one 64-bit hash word big-endian at out[0..7]. */
static void sha512_put_be64(u8 *out, u64 v)
{
    for (usz j = 0; j < 8; j++) out[j] = (u8)(v >> (56 - j * 8));
}

void quic_sha512_final(quic_sha512_ctx *s, u8 out[QUIC_SHA512_DIGEST])
{
    u8 lenbe[16];
    put_len(lenbe, s->total * 8);
    sha512_pad_message(s);
    quic_sha512_update(s, lenbe, 16);
    for (usz i = 0; i < 8; i++) sha512_put_be64(out + i * 8, s->h[i]);
}

void quic_sha512(const u8 *data, usz len, u8 out[QUIC_SHA512_DIGEST])
{
    quic_sha512_ctx s;
    quic_sha512_init(&s);
    quic_sha512_update(&s, data, len);
    quic_sha512_final(&s, out);
}
