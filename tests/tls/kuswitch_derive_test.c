#include "test.h"

/* RFC 9001 6.1: next keys come from the next secret (kuderive), key/iv are
 * re-derived from it, and hp is left unchanged. */
void test_kuswitch_derive(void) {
  u8 cur[32];
  for (usz i = 0; i < 32; i++) cur[i] = (u8)i;

  initial_keys next;
  for (usz i = 0; i < INITIAL_HP; i++) next.hp[i] = 0xAB; /* sentinel */
  u8 next_secret[32];
  kuswitch_next_keys(cur, &next, next_secret);

  /* next_secret matches the standalone kuderive output (re-uses it) */
  u8 expect_secret[32];
  ku_next_secret(cur, expect_secret);
  for (usz i = 0; i < 32; i++) CHECK(next_secret[i] == expect_secret[i]);

  /* key/iv match Expand-Label from that secret */
  u8         ek[INITIAL_KEY], ev[INITIAL_IV];
  hkdf_label lk = {"quic key", 8, {0, 0}};
  hkdf_label li = {"quic iv", 7, {0, 0}};
  hkdf_expand_label(expect_secret, &lk, wired_mspan_of(ek, INITIAL_KEY));
  hkdf_expand_label(expect_secret, &li, wired_mspan_of(ev, INITIAL_IV));
  for (usz i = 0; i < INITIAL_KEY; i++) CHECK(next.key[i] == ek[i]);
  for (usz i = 0; i < INITIAL_IV; i++) CHECK(next.iv[i] == ev[i]);

  /* RFC 9001 6.1: hp untouched */
  for (usz i = 0; i < INITIAL_HP; i++) CHECK(next.hp[i] == 0xAB);

  /* deterministic */
  initial_keys again;
  u8           again_secret[32];
  kuswitch_next_keys(cur, &again, again_secret);
  for (usz i = 0; i < INITIAL_KEY; i++) CHECK(again.key[i] == next.key[i]);
}

/* RFC 8446 5.3: TLS_CHACHA20_POLY1305_SHA256's key is 32 bytes, not the
 * fixed 16-byte AES key kuswitch_next_keys derives -- a Key Update on a
 * ChaCha20-negotiated connection needs the _suite entry point so the tail
 * 16 bytes aren't left stale (every post-update packet would otherwise fail
 * to open). */
void test_kuswitch_derive_suite_chacha20_full_key(void) {
  u8 cur[32];
  for (usz i = 0; i < 32; i++) cur[i] = (u8)i;

  initial_keys next;
  for (usz i = 0; i < AEAD_KEY_MAX; i++) next.key[i] = 0;
  u8 next_secret[32];
  kuswitch_next_keys_suite(0x1303, cur, &next, next_secret);

  u8         ek[32];
  hkdf_label lk = {"quic key", 8, {0, 0}};
  hkdf_expand_label(next_secret, &lk, wired_mspan_of(ek, 32));
  for (usz i = 0; i < 32; i++) CHECK(next.key[i] == ek[i]);
}

/* Same call, but suite 0x1301 (AES-128-GCM) derives exactly the same 16
 * bytes kuswitch_next_keys does -- the _suite entry point is a strict
 * superset, not a behavior change for the existing AES-only callers. */
void test_kuswitch_derive_suite_aes_matches_plain(void) {
  u8 cur[32];
  for (usz i = 0; i < 32; i++) cur[i] = (u8)(0x40 + i);

  initial_keys plain, suite;
  u8           plain_secret[32], suite_secret[32];
  kuswitch_next_keys(cur, &plain, plain_secret);
  kuswitch_next_keys_suite(0x1301, cur, &suite, suite_secret);

  for (usz i = 0; i < INITIAL_KEY; i++) CHECK(suite.key[i] == plain.key[i]);
  for (usz i = 0; i < INITIAL_IV; i++) CHECK(suite.iv[i] == plain.iv[i]);
}

/* RFC 9001 6.3/6.5: kuswitch_state keeps BOTH the current and the
 * immediately-prior generation ready at once (twogen.c), so a Key Update
 * never needs to generate keys inline while processing a packet -- the next
 * generation's keys are supplied to kuswitch_rotate up front, and the prior
 * generation stays available via kuswitch_key_for_phase until
 * kuswitch_discard_old runs. A phase bit naming a generation older than the
 * retained one (or before any rotation happened) is refused, not
 * regenerated on demand. */
void test_kuswitch_twogen(void) {
  initial_keys gen0 = {0}, gen1 = {0}, gen2 = {0};
  gen0.key[0] = 0xA0;
  gen1.key[0] = 0xA1;
  gen2.key[0] = 0xA2;

  kuswitch_state      st;
  const initial_keys* got;
  kuswitch_init(&st, &gen0);
  CHECK(kuswitch_key_for_phase(&st, 0, &got) == 1);
  CHECK(got->key[0] == 0xA0);
  /* generation 1 (odd phase bit) not reached yet: refused, not fabricated */
  CHECK(kuswitch_key_for_phase(&st, 1, &got) == 0);

  kuswitch_rotate(&st, &gen1);
  /* current (gen 1, phase bit 1) available immediately, no key generation
   * needed during this lookup */
  CHECK(kuswitch_key_for_phase(&st, 1, &got) == 1);
  CHECK(got->key[0] == 0xA1);
  /* old (gen 0, phase bit 0) still retained for in-flight packets */
  CHECK(kuswitch_key_for_phase(&st, 0, &got) == 1);
  CHECK(got->key[0] == 0xA0);

  kuswitch_rotate(&st, &gen2);
  /* rotating again evicts gen 0 entirely: only cur (gen2) and old (gen1)
   * remain, gen0's now-stale phase bit (0) reads as gen2's bit (also 0) */
  CHECK(kuswitch_key_for_phase(&st, 0, &got) == 1);
  CHECK(got->key[0] == 0xA2);

  kuswitch_discard_old(&st);
  /* after the retention period, the old generation is refused, not
   * regenerated */
  CHECK(kuswitch_key_for_phase(&st, 1, &got) == 0);
}
