#include "tls/keys/xkeys/xkeys.h"

#include "test.h"
#include "tls/handshake/core/tls/cipher.h"
#include "transport/packet/protect/protect_suite/aead_suite.h"
#include "transport/packet/protect/protect_suite/hp_suite.h"

/* Deterministic byte stream (LCG, no libc rand). */
static u32 xkeys_rng;

static void xkeys_fill(u8* p, usz n) {
  for (usz i = 0; i < n; i++) {
    xkeys_rng = xkeys_rng * 1664525u + 1013904223u;
    p[i]      = (u8)(xkeys_rng >> 24);
  }
}

/* 0 when a and b hold the same n bytes. */
static int xkeys_diff(const u8* a, const u8* b, usz n) {
  u8 d = 0;
  for (usz i = 0; i < n; i++) {
    d |= a[i] ^ b[i];
  }
  return d;
}

static void xkeys_keys(initial_keys* k) {
  xkeys_fill(k->key, sizeof k->key);
  xkeys_fill(k->iv, sizeof k->iv);
  xkeys_fill(k->hp, sizeof k->hp);
}

/* On only for AES-128-GCM on an AES-NI host; off for the other suites and
 * when the CPU check says no. */
static void test_xkeys_on_only_for_aes128_with_aesni(void) {
  static xkeys x;
  initial_keys k;
  xkeys_keys(&k);
  xkeys_sync(&x, TLS_AES_128_GCM_SHA256, &k);
  CHECK(x.on == gcmx86_supported());
  CHECK((xkeys_usable(&x) != 0) == gcmx86_supported());
  xkeys_sync(&x, TLS_CHACHA20_POLY1305_SHA256, &k);
  CHECK(x.on == 0 && xkeys_usable(&x) == 0);
  xkeys_sync(&x, TLS_AES_256_GCM_SHA384, &k);
  CHECK(x.on == 0);
  CHECK(xkeys_aead(0) == 0);
}

/* The header-protection mask through the expanded key equals the scalar
 * RFC 9001 5.4.3 mask, over random keys and samples. */
static void test_xkeys_hp_mask_matches_scalar(void) {
  static xkeys x;
  initial_keys k;
  u8           sample[16], want[5], got[5];
  for (usz i = 0; i < 1000 && gcmx86_supported(); i++) {
    xkeys_keys(&k);
    xkeys_fill(sample, sizeof sample);
    xkeys_sync(&x, TLS_AES_128_GCM_SHA256, &k);
    CHECK(hp_suite_mask(TLS_AES_128_GCM_SHA256, k.hp, sample, want));
    xkeys_hp_mask(&x, sample, got);
    CHECK(xkeys_diff(want, got, 5) == 0);
  }
}

/* One seal under the raw key and one under the expanded key: same bytes,
 * for sizes on both sides of the 4-block CTR lanes. */
static void xkeys_seal_pair(const xkeys* x, const initial_keys* k, usz n) {
  static u8     pt[1500], a[1516], b[1516], back[1500];
  u8            hdr[13];
  aead_suite_op raw = {TLS_AES_128_GCM_SHA256, k->key, k->iv, 0x1234 + n,
                       {hdr, sizeof hdr},      0};
  aead_suite_op exp = raw;
  exp.x             = xkeys_aead(x);
  xkeys_fill(pt, n);
  xkeys_fill(hdr, sizeof hdr);
  CHECK(aead_suite_seal(&raw, wired_span_of(pt, n), a) == n + 16);
  CHECK(aead_suite_seal(&exp, wired_span_of(pt, n), b) == n + 16);
  CHECK(xkeys_diff(a, b, n + 16) == 0);
  CHECK(aead_suite_open(&exp, wired_span_of(b, n), back) == n);
  CHECK(xkeys_diff(back, pt, n) == 0);
  b[n] ^= 1; /* a flipped tag bit is rejected on the expanded path too */
  CHECK(aead_suite_open(&exp, wired_span_of(b, n), back) == 0);
}

static void test_xkeys_aead_matches_raw_key(void) {
  static const usz sizes[] = {1, 15, 16, 17, 63, 64, 65, 150, 1200, 1452};
  static xkeys     x;
  initial_keys     k;
  if (!gcmx86_supported()) {
    return;
  }
  xkeys_keys(&k);
  xkeys_sync(&x, TLS_AES_128_GCM_SHA256, &k);
  for (usz i = 0; i < sizeof sizes / sizeof *sizes; i++) {
    xkeys_seal_pair(&x, &k, sizes[i]);
  }
}

/* An empty plaintext opens through the raw-key path even with an expanded
 * key present (gcmx86_open cannot report it), and a bad tag still fails. */
static void test_xkeys_empty_plaintext_opens(void) {
  static xkeys  x;
  initial_keys  k;
  u8            hdr[9] = {0}, ct[16], back[1];
  aead_suite_op op;
  xkeys_keys(&k);
  xkeys_sync(&x, TLS_AES_128_GCM_SHA256, &k);
  op = (aead_suite_op){
      TLS_AES_128_GCM_SHA256,      k.key, k.iv, 7, {hdr, sizeof hdr},
      xkeys_aead(xkeys_usable(&x))};
  CHECK(aead_suite_seal(&op, wired_span_of(hdr, 0), ct) == 16);
  ct[3] ^= 0x40;
  CHECK(aead_suite_open(&op, wired_span_of(ct, 0), back) == 0);
}

/* A changed key (a Key Update, or a slot's keys replaced) is picked up by
 * the next sync: the old expanded key no longer seals. An unchanged key
 * leaves the contexts untouched. */
static void test_xkeys_resync_follows_the_keys(void) {
  static xkeys x;
  initial_keys k1, k2;
  u8           sample[16] = {1, 2, 3}, m1[5], m2[5], want[5];
  if (!gcmx86_supported()) {
    return;
  }
  xkeys_keys(&k1);
  xkeys_keys(&k2);
  xkeys_sync(&x, TLS_AES_128_GCM_SHA256, &k1);
  xkeys_hp_mask(&x, sample, m1);
  x.aead.h[0] ^= 0xff; /* a marker: an unneeded rebuild would restore it */
  xkeys_sync(&x, TLS_AES_128_GCM_SHA256, &k1);
  CHECK(xkeys_diff(x.key, k1.key, 16) == 0);
  x.aead.h[0] ^= 0xff;
  xkeys_sync(&x, TLS_AES_128_GCM_SHA256, &k2);
  CHECK(xkeys_diff(x.key, k2.key, 16) == 0);
  CHECK(xkeys_diff(x.hpkey, k2.hp, 16) == 0);
  xkeys_hp_mask(&x, sample, m2);
  CHECK(hp_suite_mask(TLS_AES_128_GCM_SHA256, k2.hp, sample, want));
  CHECK(xkeys_diff(m2, want, 5) == 0);
  CHECK(xkeys_diff(m1, m2, 5) != 0);
}

void test_xkeys(void) {
  xkeys_rng = 0x786b6579;
  test_xkeys_on_only_for_aes128_with_aesni();
  test_xkeys_hp_mask_matches_scalar();
  test_xkeys_aead_matches_raw_key();
  test_xkeys_empty_plaintext_opens();
  test_xkeys_resync_follows_the_keys();
}
