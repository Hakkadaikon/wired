#include "test.h"

/* Hardware AES-128-GCM (gcmx86) vs the scalar gcm path. Every sub-test is
 * gated on gcmx86_supported(): on a CPU without AES-NI/PCLMULQDQ this
 * whole file is a no-op pass. */

/* Deterministic byte stream (LCG, no libc rand). */
static u32 gcmx86_rng;

static u8 gcmx86_rand(void) {
  gcmx86_rng = gcmx86_rng * 1664525u + 1013904223u;
  return (u8)(gcmx86_rng >> 24);
}

static void gcmx86_fill(u8* p, usz n) {
  for (usz i = 0; i < n; i++) p[i] = gcmx86_rand();
}

/* Parse hex of arbitrary even length into out; returns byte count. */
static usz gcmx86_unhex(const char* hex, u8* out) {
  usz i = 0;
  while (hex[i * 2] != 0) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    i++;
  }
  return i;
}

static void test_gcmx86_align(void) {
  static gcmx86 x;
  CHECK((usz)&x % 16 == 0);
}

/* NIST SP 800-38D test case 4 (AES-128-GCM, 60-byte pt, 20-byte AAD) — the
 * same official vector the scalar gcm_test pins. */
static void test_gcmx86_nist(void) {
  u8     key[16], iv[16], pt[64], aad[32], want_ct[64], want_tag[16];
  u8     out[64 + 16], dec[64];
  gcmx86 x;
  gcmx86_unhex("feffe9928665731c6d6a8f9467308308", key);
  gcmx86_unhex("cafebabefacedbaddecaf888", iv);
  usz pl = gcmx86_unhex(
      "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d"
      "8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657"
      "ba637b39",
      pt);
  usz al = gcmx86_unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad);
  gcmx86_unhex(
      "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
      "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
      want_ct);
  gcmx86_unhex("5bc94fbc3221a5db94fae95ae7121a47", want_tag);

  gcmx86_init(&x, key);
  CHECK(
      gcmx86_seal(&x, iv, wired_span_of(aad, al), wired_span_of(pt, pl), out) ==
      pl + 16);
  for (usz i = 0; i < pl; i++) CHECK(out[i] == want_ct[i]);
  for (usz i = 0; i < 16; i++) CHECK(out[pl + i] == want_tag[i]);
  CHECK(
      gcmx86_open(
          &x, iv, wired_span_of(aad, al), wired_span_of(out, pl + 16), dec) ==
      pl);
  for (usz i = 0; i < pl; i++) CHECK(dec[i] == pt[i]);
}

/* One differential case: scalar seal == x86 seal byte-for-byte,
 * open(seal(x)) == x, corrupted tag rejected without touching out. */
static void gcmx86_diff_one(usz n, usz an) {
  u8     key[16], nonce[12], aad[32];
  u8     pt[2048], want[2048 + 16], got[2048 + 16], dec[2048];
  aes128 a;
  gcmx86 x;
  gcmx86_fill(key, 16);
  gcmx86_fill(nonce, 12);
  gcmx86_fill(aad, an);
  gcmx86_fill(pt, n);

  aes128_init(&a, key);
  gcm_ctx g = {&a, nonce, {aad, an}};
  gcm_seal(&g, wired_span_of(pt, n), want);

  gcmx86_init(&x, key);
  CHECK(
      gcmx86_seal(
          &x, nonce, wired_span_of(aad, an), wired_span_of(pt, n), got) ==
      n + 16);
  for (usz i = 0; i < n + 16; i++) CHECK(got[i] == want[i]);

  for (usz i = 0; i < n; i++) dec[i] = 0xCC;
  CHECK(
      gcmx86_open(
          &x, nonce, wired_span_of(aad, an), wired_span_of(got, n + 16), dec) ==
      n);
  for (usz i = 0; i < n; i++) CHECK(dec[i] == pt[i]);

  /* flip one tag bit: must reject and leave the output untouched */
  for (usz i = 0; i < n; i++) dec[i] = 0xCC;
  got[n] ^= 1;
  CHECK(
      gcmx86_open(
          &x, nonce, wired_span_of(aad, an), wired_span_of(got, n + 16), dec) ==
      0);
  for (usz i = 0; i < n; i++) CHECK(dec[i] == 0xCC);
}

/* Lengths cover empty, sub-block, exact block, block+1, multi-block, the
 * 1129-byte QUIC packet hot case, and the largest test buffer. */
static void test_gcmx86_diff(void) {
  static const usz lens[] = {0, 1, 15, 16, 17, 64, 255, 1129, 2048};
  static const usz aads[] = {0, 13, 20};
  gcmx86_rng              = 0x77697265; /* deterministic across runs */
  for (usz i = 0; i < sizeof(lens) / sizeof(lens[0]); i++)
    for (usz j = 0; j < sizeof(aads) / sizeof(aads[0]); j++)
      gcmx86_diff_one(lens[i], aads[j]);
}

void test_gcmx86(void) {
  if (!gcmx86_supported()) return; /* no AES-NI: nothing to run */
  test_gcmx86_align();
  test_gcmx86_nist();
  test_gcmx86_diff();
}
