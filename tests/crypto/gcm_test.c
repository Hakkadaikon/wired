#include "test.h"

/* Parse hex of arbitrary even length into out; returns byte count. */
static usz unhex(const char* hex, u8* out) {
  usz i = 0;
  while (hex[i * 2] != 0) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    i++;
  }
  return i;
}

/* NIST SP 800-38D test case 4 (AES-128-GCM with AAD). */
static void test_gcm_nist(void) {
  u8          key[16], iv[12], pt[64], aad[32], want_ct[64], want_tag[16];
  u8          ct[64 + 16]; /* ciphertext || tag */
  quic_aes128 a;
  u8          ivbuf[16];
  unhex("feffe9928665731c6d6a8f9467308308", key);
  unhex("cafebabefacedbaddecaf888", ivbuf);
  for (usz i = 0; i < 12; i++) iv[i] = ivbuf[i];
  usz pl = unhex(
      "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d"
      "8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657"
      "ba637b39",
      pt);
  usz al = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad);
  unhex(
      "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
      "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
      want_ct);
  unhex("5bc94fbc3221a5db94fae95ae7121a47", want_tag);

  quic_aes128_init(&a, key);
  quic_gcm_ctx g = {&a, iv, {aad, al}};
  quic_gcm_seal(&g, wired_span_of(pt, pl), ct);
  for (usz i = 0; i < pl; i++) CHECK(ct[i] == want_ct[i]);
  for (usz i = 0; i < 16; i++) CHECK(ct[pl + i] == want_tag[i]);
}

/* Round-trip plus tamper detection (prover: AUTH_FAIL leaves pt untouched). */
static void test_gcm_open(void) {
  u8          key[16] = {0}, iv[12] = {0};
  u8          pt[20], ct[36], dec[20]; /* ct = ciphertext || tag */
  quic_aes128 a;
  for (usz i = 0; i < 20; i++) {
    pt[i]  = (u8)i;
    dec[i] = 0xCC;
  }
  quic_aes128_init(&a, key);
  quic_gcm_ctx g = {&a, iv, {(const u8*)"hdr", 3}};
  quic_gcm_seal(&g, wired_span_of(pt, 20), ct);

  CHECK(quic_gcm_open(&g, wired_span_of(ct, 36), dec) == 1);
  for (usz i = 0; i < 20; i++) CHECK(dec[i] == pt[i]);

  /* flip one tag bit: must reject and not overwrite dec */
  for (usz i = 0; i < 20; i++) dec[i] = 0xCC;
  u8 bad[36];
  for (usz i = 0; i < 36; i++) bad[i] = ct[i];
  bad[20] ^= 1;
  CHECK(quic_gcm_open(&g, wired_span_of(bad, 36), dec) == 0);
  for (usz i = 0; i < 20; i++) CHECK(dec[i] == 0xCC);

  /* flip one AAD byte: must reject */
  quic_gcm_ctx g2 = {&a, iv, {(const u8*)"HDR", 3}};
  CHECK(quic_gcm_open(&g2, wired_span_of(ct, 36), dec) == 0);
}

/* Deterministic byte stream (LCG, no libc rand) for the differential check
 * below. */
static u32 gcm_diff_rng;

static u8 gcm_diff_rand(void) {
  gcm_diff_rng = gcm_diff_rng * 1664525u + 1013904223u;
  return (u8)(gcm_diff_rng >> 24);
}

static void gcm_diff_fill(u8* p, usz n) {
  for (usz i = 0; i < n; i++) p[i] = gcm_diff_rand();
}

/* quic_gcm_seal/open dispatch to AES-NI when available (gcm.c). This is the
 * scalar oracle side of that differential: it exercises whichever path
 * quic_gcm_seal/open picks at runtime, for lengths spanning empty, sub-
 * block, exact block, multi-block and the 1129-byte QUIC hot case. On a host
 * without AES-NI this is exactly the scalar path already covered above, so
 * the check still runs (it is not gated on quic_gcmx86_supported()). */
static void gcm_dispatch_one(usz n, usz an) {
  u8          key[16], nonce[12], aad[32];
  u8          pt[2048], ct[2048 + 16], dec[2048];
  quic_aes128 a;
  gcm_diff_fill(key, 16);
  gcm_diff_fill(nonce, 12);
  gcm_diff_fill(aad, an);
  gcm_diff_fill(pt, n);
  quic_aes128_init(&a, key);
  quic_gcm_ctx g = {&a, nonce, {aad, an}};

  CHECK(quic_gcm_seal(&g, wired_span_of(pt, n), ct) == n + 16);
  for (usz i = 0; i < n; i++) dec[i] = 0xCC;
  CHECK(quic_gcm_open(&g, wired_span_of(ct, n + 16), dec) == 1);
  for (usz i = 0; i < n; i++) CHECK(dec[i] == pt[i]);

  /* flip one tag bit: must reject and leave dec untouched */
  for (usz i = 0; i < n; i++) dec[i] = 0xCC;
  ct[n] ^= 1;
  CHECK(quic_gcm_open(&g, wired_span_of(ct, n + 16), dec) == 0);
  for (usz i = 0; i < n; i++) CHECK(dec[i] == 0xCC);
}

static void test_gcm_dispatch(void) {
  static const usz lens[] = {0, 1, 15, 16, 17, 64, 255, 1129, 2048};
  static const usz aads[] = {0, 13, 20};
  gcm_diff_rng            = 0x77697265;
  for (usz i = 0; i < sizeof(lens) / sizeof(lens[0]); i++)
    for (usz j = 0; j < sizeof(aads) / sizeof(aads[0]); j++)
      gcm_dispatch_one(lens[i], aads[j]);
}

void test_gcm(void) {
  test_gcm_nist();
  test_gcm_open();
  test_gcm_dispatch();
}
