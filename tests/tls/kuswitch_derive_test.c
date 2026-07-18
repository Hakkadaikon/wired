#include "test.h"

/* RFC 9001 6.1: next keys come from the next secret (kuderive), key/iv are
 * re-derived from it, and hp is left unchanged. */
void test_kuswitch_derive(void) {
  u8 cur[32];
  for (usz i = 0; i < 32; i++) cur[i] = (u8)i;

  quic_initial_keys next;
  for (usz i = 0; i < QUIC_INITIAL_HP; i++) next.hp[i] = 0xAB; /* sentinel */
  u8 next_secret[32];
  quic_kuswitch_next_keys(cur, &next, next_secret);

  /* next_secret matches the standalone kuderive output (re-uses it) */
  u8 expect_secret[32];
  quic_ku_next_secret(cur, expect_secret);
  for (usz i = 0; i < 32; i++) CHECK(next_secret[i] == expect_secret[i]);

  /* key/iv match Expand-Label from that secret */
  u8              ek[QUIC_INITIAL_KEY], ev[QUIC_INITIAL_IV];
  quic_hkdf_label lk = {"quic key", 8, {0, 0}};
  quic_hkdf_label li = {"quic iv", 7, {0, 0}};
  quic_hkdf_expand_label(
      expect_secret, &lk, quic_mspan_of(ek, QUIC_INITIAL_KEY));
  quic_hkdf_expand_label(
      expect_secret, &li, quic_mspan_of(ev, QUIC_INITIAL_IV));
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(next.key[i] == ek[i]);
  for (usz i = 0; i < QUIC_INITIAL_IV; i++) CHECK(next.iv[i] == ev[i]);

  /* RFC 9001 6.1: hp untouched */
  for (usz i = 0; i < QUIC_INITIAL_HP; i++) CHECK(next.hp[i] == 0xAB);

  /* deterministic */
  quic_initial_keys again;
  u8                again_secret[32];
  quic_kuswitch_next_keys(cur, &again, again_secret);
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(again.key[i] == next.key[i]);
}

/* RFC 8446 5.3: TLS_CHACHA20_POLY1305_SHA256's key is 32 bytes, not the
 * fixed 16-byte AES key quic_kuswitch_next_keys derives -- a Key Update on a
 * ChaCha20-negotiated connection needs the _suite entry point so the tail
 * 16 bytes aren't left stale (every post-update packet would otherwise fail
 * to open, observed live against a real quic-go chacha20 interop client
 * that stalls at PTO after its first Key Update). */
void test_kuswitch_derive_suite_chacha20_full_key(void) {
  u8 cur[32];
  for (usz i = 0; i < 32; i++) cur[i] = (u8)i;

  quic_initial_keys next;
  for (usz i = 0; i < QUIC_AEAD_KEY_MAX; i++) next.key[i] = 0;
  u8 next_secret[32];
  quic_kuswitch_next_keys_suite(0x1303, cur, &next, next_secret);

  u8              ek[32];
  quic_hkdf_label lk = {"quic key", 8, {0, 0}};
  quic_hkdf_expand_label(next_secret, &lk, quic_mspan_of(ek, 32));
  for (usz i = 0; i < 32; i++) CHECK(next.key[i] == ek[i]);
}

/* Same call, but suite 0x1301 (AES-128-GCM) derives exactly the same 16
 * bytes quic_kuswitch_next_keys does -- the _suite entry point is a strict
 * superset, not a behavior change for the existing AES-only callers. */
void test_kuswitch_derive_suite_aes_matches_plain(void) {
  u8 cur[32];
  for (usz i = 0; i < 32; i++) cur[i] = (u8)(0x40 + i);

  quic_initial_keys plain, suite;
  u8                plain_secret[32], suite_secret[32];
  quic_kuswitch_next_keys(cur, &plain, plain_secret);
  quic_kuswitch_next_keys_suite(0x1301, cur, &suite, suite_secret);

  for (usz i = 0; i < QUIC_INITIAL_KEY; i++)
    CHECK(suite.key[i] == plain.key[i]);
  for (usz i = 0; i < QUIC_INITIAL_IV; i++) CHECK(suite.iv[i] == plain.iv[i]);
}
