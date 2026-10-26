#include "test.h"

/* RFC 9001 6.1: next keys come from the next secret (kuderive), key/iv are
 * re-derived from it, and hp is left unchanged. */
void test_kuswitch_derive(void) {
  u8 cur[32];
  for (usz i = 0; i < 32; i++) {
    cur[i] = (u8)i;
  }

  initial_keys next;
  for (usz i = 0; i < INITIAL_HP; i++) {
    next.hp[i] = 0xAB; /* sentinel */
  }
  u8 next_secret[32];
  kuswitch_next_keys(cur, &next, next_secret);

  /* next_secret matches the standalone kuderive output (re-uses it) */
  u8 expect_secret[32];
  ku_next_secret(cur, expect_secret);
  for (usz i = 0; i < 32; i++) {
    CHECK(next_secret[i] == expect_secret[i]);
  }

  /* key/iv match Expand-Label from that secret */
  u8         ek[INITIAL_KEY], ev[INITIAL_IV];
  hkdf_label lk = {"quic key", 8, {0, 0}};
  hkdf_label li = {"quic iv", 7, {0, 0}};
  hkdf_expand_label(expect_secret, &lk, wired_mspan_of(ek, INITIAL_KEY));
  hkdf_expand_label(expect_secret, &li, wired_mspan_of(ev, INITIAL_IV));
  for (usz i = 0; i < INITIAL_KEY; i++) {
    CHECK(next.key[i] == ek[i]);
  }
  for (usz i = 0; i < INITIAL_IV; i++) {
    CHECK(next.iv[i] == ev[i]);
  }

  /* RFC 9001 6.1: hp untouched */
  for (usz i = 0; i < INITIAL_HP; i++) {
    CHECK(next.hp[i] == 0xAB);
  }

  /* deterministic */
  initial_keys again;
  u8           again_secret[32];
  kuswitch_next_keys(cur, &again, again_secret);
  for (usz i = 0; i < INITIAL_KEY; i++) {
    CHECK(again.key[i] == next.key[i]);
  }
}

/* RFC 8446 5.3: TLS_CHACHA20_POLY1305_SHA256's key is 32 bytes, not the
 * fixed 16-byte AES key kuswitch_next_keys derives -- a Key Update on a
 * ChaCha20-negotiated connection needs the _suite entry point so the tail
 * 16 bytes aren't left stale (every post-update packet would otherwise fail
 * to open). */
void test_kuswitch_derive_suite_chacha20_full_key(void) {
  u8 cur[32];
  for (usz i = 0; i < 32; i++) {
    cur[i] = (u8)i;
  }

  initial_keys next;
  for (usz i = 0; i < AEAD_KEY_MAX; i++) {
    next.key[i] = 0;
  }
  u8 next_secret[32];
  kuswitch_next_keys_suite(0x1303, VERSION_1, cur, &next, next_secret);

  u8         ek[32];
  hkdf_label lk = {"quic key", 8, {0, 0}};
  hkdf_expand_label(next_secret, &lk, wired_mspan_of(ek, 32));
  for (usz i = 0; i < 32; i++) {
    CHECK(next.key[i] == ek[i]);
  }
}

/* Same call, but suite 0x1301 (AES-128-GCM) derives exactly the same 16
 * bytes kuswitch_next_keys does -- the _suite entry point is a strict
 * superset, not a behavior change for the existing AES-only callers. */
void test_kuswitch_derive_suite_aes_matches_plain(void) {
  u8 cur[32];
  for (usz i = 0; i < 32; i++) {
    cur[i] = (u8)(0x40 + i);
  }

  initial_keys plain, suite;
  u8           plain_secret[32], suite_secret[32];
  kuswitch_next_keys(cur, &plain, plain_secret);
  kuswitch_next_keys_suite(0x1301, VERSION_1, cur, &suite, suite_secret);

  for (usz i = 0; i < INITIAL_KEY; i++) {
    CHECK(suite.key[i] == plain.key[i]);
  }
  for (usz i = 0; i < INITIAL_IV; i++) {
    CHECK(suite.iv[i] == plain.iv[i]);
  }
}

/* RFC 9369 3.3.2: a v2 Key Update uses "quicv2 ku"/"quicv2 key"/"quicv2 iv".
 * From RFC 9369 A.5's ChaCha20 write secret the next secret must be A.5's
 * "ku" value; key/iv were computed independently (Python HKDF-Expand-Label
 * over that "ku" value with the "quicv2 " labels) -- the v1 "quic key" label
 * would give 4bd9cdca... instead. hp stays untouched. */
void test_kuswitch_derive_suite_v2_labels(void) {
  static const u8 secret[32] = {0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e,
                                0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
                                0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60,
                                0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b};
  static const u8 want_ku[32] = {
      0xc6, 0x93, 0x74, 0xc4, 0x9e, 0x3d, 0x2a, 0x94, 0x66, 0xfa, 0x68,
      0x9e, 0x49, 0xd4, 0x76, 0xdb, 0x5d, 0x0d, 0xfb, 0xc8, 0x7d, 0x32,
      0xce, 0xea, 0xa6, 0x34, 0x3f, 0xd0, 0xae, 0x4c, 0x7d, 0x88};
  static const u8 want_key[32] = {
      0x6e, 0x52, 0xfc, 0xe7, 0x8e, 0x1e, 0x3b, 0x19, 0xbe, 0x65, 0x7e,
      0x40, 0x7b, 0xe4, 0x5a, 0x7c, 0x6c, 0x02, 0x4c, 0x87, 0x73, 0x0b,
      0x30, 0x9e, 0x20, 0xc9, 0x68, 0x22, 0x32, 0xe9, 0x88, 0x23};
  static const u8 want_iv[12] = {0x57, 0xd1, 0x02, 0x98, 0x56, 0x82,
                                 0x0c, 0x70, 0x3b, 0xfe, 0x66, 0x03};
  initial_keys    next;
  u8              next_secret[32];
  for (usz i = 0; i < AEAD_KEY_MAX; i++) {
    next.hp[i] = 0xAB; /* sentinel */
  }
  kuswitch_next_keys_suite(0x1303, VERSION_2, secret, &next, next_secret);
  for (usz i = 0; i < 32; i++) {
    CHECK(next_secret[i] == want_ku[i]);
    CHECK(next.key[i] == want_key[i]);
    CHECK(next.hp[i] == 0xAB);
  }
  for (usz i = 0; i < 12; i++) {
    CHECK(next.iv[i] == want_iv[i]);
  }
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
  /* RFC 9001 6.5: a discarded key is gone from memory too, not just
   * unreachable -- every byte of the old generation reads zero */
  {
    const u8* p   = (const u8*)&st.old;
    u8        any = 0;
    for (usz i = 0; i < sizeof st.old; i++) {
      any |= p[i];
    }
    CHECK(any == 0);
  }
}
