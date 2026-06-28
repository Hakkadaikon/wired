#include "ed25519/ed25519.h"
#include "hash/sha512.h"

/* RFC 8032 Section 5.1 Ed25519 verify. Field GF(2^255-19) as five 51-bit
 * limbs (radix-2^51, ref10 style; same representation as RFC 7748 X25519). */

typedef u64 fe[5];
#define MASK51 0x7ffffffffffffULL

static void fe_0(fe h) { for (usz i = 0; i < 5; i++) h[i] = 0; }
static void fe_1(fe h) { fe_0(h); h[0] = 1; }
static void fe_copy(fe h, const fe f) { for (usz i = 0; i < 5; i++) h[i] = f[i]; }

static void fe_add(fe h, const fe f, const fe g)
{
    for (usz i = 0; i < 5; i++) h[i] = f[i] + g[i];
}

/* h = f - g (mod p), adding 2p first to stay non-negative. */
static void fe_sub(fe h, const fe f, const fe g)
{
    static const u64 twop[5] = {
        0xfffffffffffdaULL, 0xffffffffffffeULL, 0xffffffffffffeULL,
        0xffffffffffffeULL, 0xffffffffffffeULL
    };
    for (usz i = 0; i < 5; i++) h[i] = f[i] + twop[i] - g[i];
}

/* One column of the schoolbook product with the 19-fold wrap past 2^255. */
static unsigned __int128 mul_col(const fe f, const fe g, usz i)
{
    unsigned __int128 t = 0;
    for (usz j = 0; j < 5; j++) {
        u64 gj = (i >= j) ? g[i - j] : g[5 + i - j] * 19;
        t += (unsigned __int128)f[j] * gj;
    }
    return t;
}

/* Reduce five 128-bit column sums to 51-bit limbs via a carry chain. */
static void fe_reduce(fe h, unsigned __int128 t[5])
{
    u64 c = 0;
    for (usz i = 0; i < 5; i++) {
        t[i] += c;
        h[i] = (u64)t[i] & MASK51;
        c = (u64)(t[i] >> 51);
    }
    h[0] += c * 19;
    h[1] += h[0] >> 51;
    h[0] &= MASK51;
}

static void fe_mul(fe h, const fe f, const fe g)
{
    unsigned __int128 t[5];
    for (usz i = 0; i < 5; i++) t[i] = mul_col(f, g, i);
    fe_reduce(h, t);
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

/* Repeated squaring: out = in^(2^n). */
static void fe_sqn(fe out, const fe in, usz n)
{
    fe_copy(out, in);
    for (usz i = 0; i < n; i++) fe_sq(out, out);
}

/* z = f^(p-2): modular inverse via the standard ref10 addition chain. */
static void fe_invert(fe out, const fe z)
{
    fe t0, t1, t2, t3;
    fe_sq(t0, z); fe_sqn(t1, t0, 2); fe_mul(t1, z, t1); fe_mul(t0, t0, t1);
    fe_sq(t2, t0); fe_mul(t1, t1, t2); fe_sqn(t2, t1, 5); fe_mul(t1, t2, t1);
    fe_sqn(t2, t1, 10); fe_mul(t2, t2, t1); fe_sqn(t3, t2, 20); fe_mul(t2, t3, t2);
    fe_sqn(t2, t2, 10); fe_mul(t1, t2, t1); fe_sqn(t2, t1, 50); fe_mul(t2, t2, t1);
    fe_sqn(t3, t2, 100); fe_mul(t2, t3, t2); fe_sqn(t2, t2, 50); fe_mul(t1, t2, t1);
    fe_sqn(t1, t1, 5); fe_mul(out, t1, t0);
}

/* out = z^((p-5)/8), the exponent used for the candidate square root. */
static void fe_pow_p58(fe out, const fe z)
{
    fe t0, t1, t2;
    fe_sq(t0, z); fe_sqn(t1, t0, 2); fe_mul(t1, z, t1); fe_mul(t0, t0, t1);
    fe_sq(t0, t0); fe_mul(t0, t1, t0); fe_sqn(t1, t0, 5); fe_mul(t0, t1, t0);
    fe_sqn(t1, t0, 10); fe_mul(t1, t1, t0); fe_sqn(t2, t1, 20); fe_mul(t1, t2, t1);
    fe_sqn(t1, t1, 10); fe_mul(t0, t1, t0); fe_sqn(t1, t0, 50); fe_mul(t1, t1, t0);
    fe_sqn(t2, t1, 100); fe_mul(t1, t2, t1); fe_sqn(t1, t1, 50); fe_mul(t0, t1, t0);
    fe_sq(t0, t0); fe_sq(t0, t0); fe_mul(out, t0, z);
}

/* Load 32 little-endian bytes into limbs (top bit of byte 31 is cleared). */
static void fe_frombytes(fe h, const u8 *s)
{
    u64 t[4];
    for (usz i = 0; i < 4; i++) {
        t[i] = 0;
        for (usz j = 0; j < 8; j++) t[i] |= (u64)s[i * 8 + j] << (8 * j);
    }
    h[0] = t[0] & MASK51;
    h[1] = ((t[0] >> 51) | (t[1] << 13)) & MASK51;
    h[2] = ((t[1] >> 38) | (t[2] << 26)) & MASK51;
    h[3] = ((t[2] >> 25) | (t[3] << 39)) & MASK51;
    h[4] = (t[3] >> 12) & MASK51;
}

/* Pack five reduced 51-bit limbs into 32 little-endian bytes. */
static void store_reduced(u8 *s, const fe r)
{
    u64 w[4];
    w[0] = r[0] | (r[1] << 51);
    w[1] = (r[1] >> 13) | (r[2] << 38);
    w[2] = (r[2] >> 26) | (r[3] << 25);
    w[3] = (r[3] >> 39) | (r[4] << 12);
    for (usz i = 0; i < 4; i++)
        for (usz j = 0; j < 8; j++) s[i * 8 + j] = (u8)(w[i] >> (8 * j));
}

/* One weak-carry pass: every limb < 2^51, top carry folded by 19. */
static void carry_pass(fe r)
{
    u64 c = 0;
    for (usz i = 0; i < 5; i++) { r[i] += c; c = r[i] >> 51; r[i] &= MASK51; }
    r[0] += c * 19;
}

/* Fully reduce h mod p and store 32 little-endian bytes. */
static void fe_tobytes(u8 *s, const fe h)
{
    fe r;
    u64 q;
    fe_copy(r, h);
    carry_pass(r); carry_pass(r);
    q = (r[0] + 19) >> 51;
    for (usz i = 1; i < 5; i++) q = (r[i] + q) >> 51;
    r[0] += 19 * q;
    carry_pass(r);
    store_reduced(s, r);
}

/* h = -f (mod p). Carry-normalize f first so its limbs stay within the 2p
 * margin fe_sub relies on. */
static void fe_neg(fe h, const fe f)
{
    fe z, r;
    fe_0(z);
    fe_copy(r, f);
    carry_pass(r); carry_pass(r);
    fe_sub(h, z, r);
}

static int fe_isnonzero(const fe f)
{
    u8 s[32];
    u8 acc = 0;
    fe_tobytes(s, f);
    for (usz i = 0; i < 32; i++) acc |= s[i];
    return acc != 0;
}

/* Least significant bit of the canonical representative. */
static int fe_isnegative(const fe f)
{
    u8 s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

/* a == b (mod p), compared by canonical 32-byte encoding. */
static int fe_equal(const fe a, const fe b)
{
    u8 sa[32], sb[32];
    u8 diff = 0;
    fe_tobytes(sa, a);
    fe_tobytes(sb, b);
    for (usz i = 0; i < 32; i++) diff |= sa[i] ^ sb[i];
    return diff == 0;
}

/* Constant-time-ish conditional move: h <- g when cond != 0. */
static void fe_cmov(fe h, const fe g, int cond)
{
    u64 mask = (u64)(0 - (u64)(cond != 0));
    for (usz i = 0; i < 5; i++) h[i] ^= mask & (h[i] ^ g[i]);
}

/* sqrt(-1) mod p, needed when v*x^2 = -u (RFC 8032 5.1.3 case 2). */
static void fe_sqrtm1(fe out)
{
    static const u8 b[32] = {
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f,
        0xad, 0x06, 0x18, 0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00,
        0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b
    };
    fe_frombytes(out, b);
}

/* Ed25519 curve constant d (RFC 8032 5.1) loaded into a field element. */
static void fe_d(fe out)
{
    static const u8 b[32] = {
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41,
        0x41, 0x4d, 0x0a, 0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40,
        0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
    };
    fe_frombytes(out, b);
}

/* Extended homogeneous coordinates (X, Y, Z, T) (RFC 8032 5.1.4). */
typedef struct { fe X, Y, Z, T; } ge;

static void ge_zero(ge *p) { fe_0(p->X); fe_1(p->Y); fe_1(p->Z); fe_0(p->T); }

/* Base point B (RFC 8032 5.1) as an extended-coordinate point. */
static void ge_base(ge *p)
{
    static const u8 bx[32] = {
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25,
        0x95, 0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2,
        0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21
    };
    static const u8 by[32] = {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    };
    fe_frombytes(p->X, bx);
    fe_frombytes(p->Y, by);
    fe_1(p->Z);
    fe_mul(p->T, p->X, p->Y);
}

/* p3 = p1 + p2 on the twisted Edwards curve (RFC 8032 5.1.4 add formulas). */
static void ge_add(ge *p3, const ge *p1, const ge *p2)
{
    fe a, b, c, d, e, f, g, h, t, d2;
    fe_d(d2); fe_add(d2, d2, d2);            /* 2*d */
    fe_sub(a, p1->Y, p1->X); fe_sub(t, p2->Y, p2->X); fe_mul(a, a, t);
    fe_add(b, p1->Y, p1->X); fe_add(t, p2->Y, p2->X); fe_mul(b, b, t);
    fe_mul(c, p1->T, p2->T); fe_mul(c, c, d2);
    fe_mul(d, p1->Z, p2->Z); fe_add(d, d, d);
    fe_sub(e, b, a); fe_sub(f, d, c); fe_add(g, d, c); fe_add(h, b, a);
    fe_mul(p3->X, e, f); fe_mul(p3->Y, g, h);
    fe_mul(p3->T, e, h); fe_mul(p3->Z, f, g);
}

/* q = [scalar]p for a 256-bit little-endian scalar (double-and-add, MSB
 * first). Verification only, so constant time is not required. */
static void ge_scalarmult(ge *q, const u8 scalar[32], const ge *p)
{
    ge_zero(q);
    for (usz i = 256; i-- > 0;) {
        u8 bit = (scalar[i >> 3] >> (i & 7)) & 1;
        ge_add(q, q, q);
        ge t;
        ge_add(&t, q, p);
        fe_cmov(q->X, t.X, bit); fe_cmov(q->Y, t.Y, bit);
        fe_cmov(q->Z, t.Z, bit); fe_cmov(q->T, t.T, bit);
    }
}

/* Encode an extended point to 32 bytes (RFC 8032 5.1.2). */
static void ge_encode(u8 out[32], const ge *p)
{
    fe zi, x, y;
    fe_invert(zi, p->Z);
    fe_mul(x, p->X, zi);
    fe_mul(y, p->Y, zi);
    fe_tobytes(out, y);
    out[31] ^= (u8)(fe_isnegative(x) << 7);
}

/* Recover x from (u/v) per RFC 8032 5.1.3 step 2-3; returns 1 on success. */
static int recover_x(fe x, const fe u, const fe v)
{
    fe v3, uv7, t, vx2, nu;
    fe_sq(v3, v); fe_mul(v3, v3, v);                 /* v^3 */
    fe_sq(uv7, v3); fe_mul(uv7, uv7, v); fe_mul(uv7, uv7, u); /* u v^7 */
    fe_pow_p58(t, uv7);
    fe_mul(x, v3, u); fe_mul(x, x, t);               /* x = u v^3 (uv^7)^((p-5)/8) */
    fe_sq(vx2, x); fe_mul(vx2, vx2, v);
    fe_neg(nu, u);
    if (fe_equal(vx2, u)) return 1;
    fe_sqrtm1(t); fe_mul(x, x, t);
    return fe_equal(vx2, nu);
}

/* x is zero while the sign bit x_0 demands x_0 = 1 (RFC 8032 5.1.3 step 4). */
static int decode_sign_fails(const fe x, int x_0)
{
    return !fe_isnonzero(x) && x_0;
}

/* Select the square root whose parity matches x_0 (RFC 8032 5.1.3 step 4). */
static void apply_sign(fe x, int x_0)
{
    fe nx;
    fe_neg(nx, x);
    fe_cmov(x, nx, x_0 != fe_isnegative(x));
}

/* u = y^2 - 1 and v = d y^2 + 1 from the decoded y (RFC 8032 5.1.3 step 2). */
static void decode_uv(fe u, fe v, const fe y)
{
    fe one, dd;
    fe_1(one);
    fe_sq(u, y); fe_sub(u, u, one);
    fe_d(dd); fe_mul(v, u, dd); fe_add(v, v, dd); fe_add(v, v, one);
}

/* Decode a 32-byte point into extended coordinates (RFC 8032 5.1.3).
 * Returns 1 on success, 0 if the point is not on the curve. */
static int ge_decode(ge *p, const u8 in[32])
{
    fe u, v;
    int x_0 = in[31] >> 7;
    fe_frombytes(p->Y, in);
    decode_uv(u, v, p->Y);
    if (!recover_x(p->X, u, v)) return 0;
    if (decode_sign_fails(p->X, x_0)) return 0;
    apply_sign(p->X, x_0);
    fe_1(p->Z); fe_mul(p->T, p->X, p->Y);
    return 1;
}

/* L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
static const u8 ORDER_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* a >= b for 32-byte little-endian integers. */
static int sc_ge(const u8 a[32], const u8 b[32])
{
    for (usz i = 32; i-- > 0;) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return 1;
}

/* r -= L (32-byte little-endian, assumes r >= L). */
static void sc_subl(u8 r[32])
{
    int borrow = 0;
    for (usz i = 0; i < 32; i++) {
        int v = (int)r[i] - ORDER_L[i] - borrow;
        borrow = v < 0;
        r[i] = (u8)(v + (borrow << 8));
    }
}

/* r = (r << 1) | bit; returns the bit shifted out past 256 bits. */
static int sc_shl1(u8 r[32], int bit)
{
    int carry = bit;
    for (usz i = 0; i < 32; i++) {
        int v = (r[i] << 1) | carry;
        r[i] = (u8)v;
        carry = v >> 8;
    }
    return carry;
}

/* r = (r << 1) | bit then conditionally reduce mod L. */
static void sc_dbl_add_bit(u8 r[32], int bit)
{
    int overflow = sc_shl1(r, bit);
    int reduce = overflow | sc_ge(r, ORDER_L);
    if (reduce) sc_subl(r);
}

/* out = in (64-byte LE) mod L, via bitwise shift-and-reduce (RFC 8032: the
 * digest is reduced mod the group order). */
static void sc_reduce64(u8 out[32], const u8 in[64])
{
    for (usz i = 0; i < 32; i++) out[i] = 0;
    for (usz i = 512; i-- > 0;)
        sc_dbl_add_bit(out, (in[i >> 3] >> (i & 7)) & 1);
}

/* k = SHA-512(R || A || M) mod L (RFC 8032 5.1.7 step 2). */
static void hash_k(u8 k[32], const u8 *R, const u8 *A,
                   const u8 *msg, usz msg_len)
{
    quic_sha512_ctx h;
    u8 digest[64];
    quic_sha512_init(&h);
    quic_sha512_update(&h, R, 32);
    quic_sha512_update(&h, A, 32);
    quic_sha512_update(&h, msg, msg_len);
    quic_sha512_final(&h, digest);
    sc_reduce64(k, digest);
}

static int bytes_equal(const u8 a[32], const u8 b[32])
{
    u8 diff = 0;
    for (usz i = 0; i < 32; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* rhs = R + [k]A' as 32-byte encoding; returns 1 on success (R decodes). */
static int compute_rhs(u8 out[32], const u8 k[32], const ge *A, const u8 R[32])
{
    ge kA, rhs;
    ge_scalarmult(&kA, k, A);
    if (!ge_decode(&rhs, R)) return 0;
    ge_add(&rhs, &rhs, &kA);
    ge_encode(out, &rhs);
    return 1;
}

/* Final check: [S]B == R + [k]A' (RFC 8032 5.1.7 step 3, sufficient form). */
static int check_equation(const u8 S[32], const u8 k[32],
                          const ge *A, const u8 R[32])
{
    ge B, sB;
    u8 lhs[32], want[32];
    if (!compute_rhs(want, k, A, R)) return 0;
    ge_base(&B);
    ge_scalarmult(&sB, S, &B);
    ge_encode(lhs, &sB);
    return bytes_equal(lhs, want);
}

/* Accumulate a[i]*b into the schoolbook column array at offset i. */
static void sc_mul_row(u64 t[64], const u8 a[32], const u8 b[32], usz i)
{
    for (usz j = 0; j < 32; j++) t[i + j] += (u64)a[i] * b[j];
}

/* 256x256 -> 512-bit product of two 32-byte little-endian scalars. */
static void sc_mul512(u8 out[64], const u8 a[32], const u8 b[32])
{
    u64 t[64] = {0};
    u64 c = 0;
    for (usz i = 0; i < 32; i++) sc_mul_row(t, a, b, i);
    for (usz i = 0; i < 64; i++) { t[i] += c; out[i] = (u8)t[i]; c = t[i] >> 8; }
}

/* prod512 += c (32-byte LE addend) with carry. */
static void sc_add32(u8 prod[64], const u8 c[32])
{
    int carry = 0;
    for (usz i = 0; i < 64; i++) {
        int v = prod[i] + carry + (i < 32 ? c[i] : 0);
        prod[i] = (u8)v;
        carry = v >> 8;
    }
}

/* s = (a*b + c) mod L (RFC 8032 5.1.6 step 4: S = (r + k*a) mod L). */
static void sc_muladd(u8 s[32], const u8 a[32], const u8 b[32], const u8 c[32])
{
    u8 prod[64];
    sc_mul512(prod, a, b);
    sc_add32(prod, c);
    sc_reduce64(s, prod);
}

/* Apply the RFC 8032 5.1.5 clamping to a 32-byte scalar in place. */
static void sc_clamp(u8 a[32])
{
    a[0] &= 0xf8;
    a[31] &= 0x7f;
    a[31] |= 0x40;
}

/* Public key A = [clamp(SHA512(seed)[0:32])]B encoded (RFC 8032 5.1.5). */
int quic_ed25519_keypair(const u8 seed[QUIC_ED25519_SEED],
                         u8 public_key[QUIC_ED25519_PUBKEY])
{
    u8 h[64], a[32];
    ge B, A;
    quic_sha512(seed, 32, h);
    for (usz i = 0; i < 32; i++) a[i] = h[i];
    sc_clamp(a);
    ge_base(&B);
    ge_scalarmult(&A, a, &B);
    ge_encode(public_key, &A);
    return 1;
}

/* r = SHA512(prefix || msg) mod L (RFC 8032 5.1.6 step 2). */
static void hash_r(u8 r[32], const u8 prefix[32], const u8 *msg, usz msg_len)
{
    quic_sha512_ctx h;
    u8 digest[64];
    quic_sha512_init(&h);
    quic_sha512_update(&h, prefix, 32);
    quic_sha512_update(&h, msg, msg_len);
    quic_sha512_final(&h, digest);
    sc_reduce64(r, digest);
}

/* sig = R || S where R = [r]B, S = (r + k*a) mod L (RFC 8032 5.1.6). */
int quic_ed25519_sign(const u8 seed[QUIC_ED25519_SEED],
                      const u8 *msg, usz msg_len,
                      u8 sig[QUIC_ED25519_SIG])
{
    u8 h[64], a[32], r[32], k[32];
    u8 A_enc[32];
    ge B, R, A;
    quic_sha512(seed, 32, h);
    for (usz i = 0; i < 32; i++) a[i] = h[i];
    sc_clamp(a);
    ge_base(&B);
    ge_scalarmult(&A, a, &B);
    ge_encode(A_enc, &A);
    hash_r(r, h + 32, msg, msg_len);
    ge_scalarmult(&R, r, &B);
    ge_encode(sig, &R);
    hash_k(k, sig, A_enc, msg, msg_len);
    sc_muladd(sig + 32, k, a, r);
    return 1;
}

int quic_ed25519_verify(const u8 sig[QUIC_ED25519_SIG],
                        const u8 *msg, usz msg_len,
                        const u8 pubkey[QUIC_ED25519_PUBKEY])
{
    ge A;
    u8 k[32];
    const u8 *R = sig;
    const u8 *S = sig + 32;
    if (sc_ge(S, ORDER_L)) return 0;              /* S must be < L */
    if (!ge_decode(&A, pubkey)) return 0;
    hash_k(k, R, pubkey, msg, msg_len);
    return check_equation(S, k, &A, R);
}
