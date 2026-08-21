#include "test.h"

/* Both peers feed the same ECDHE secret into the schedule and arrive at the
 * same handshake secret (this is what lets them agree on traffic keys). */
static void test_schedule_agreement(void) {
  u8 ecdhe[32];
  for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(i + 1);
  u8 hs_a[32], hs_b[32];
  tls_handshake_secret(ecdhe, hs_a);
  tls_handshake_secret(ecdhe, hs_b);
  for (usz i = 0; i < 32; i++) CHECK(hs_a[i] == hs_b[i]); /* deterministic */
}

/* Client and server derive distinct directions, but each side computing the
 * peer's direction matches: client's "s hs traffic" == server's own keys. */
static void test_schedule_directions(void) {
  u8 ecdhe[32], hs[32];
  for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(0xA0 + i);
  tls_handshake_secret(ecdhe, hs);
  const u8 transcript[] = "ClientHello||ServerHello";

  initial_keys c_keys, s_keys, s_keys_from_client;
  tls_handshake_keys(
      &(handshake_keys_in){
          hs, wired_span_of(transcript, sizeof(transcript)), 0, 0},
      &c_keys);
  tls_handshake_keys(
      &(handshake_keys_in){
          hs, wired_span_of(transcript, sizeof(transcript)), 1, 0},
      &s_keys);
  tls_handshake_keys(
      &(handshake_keys_in){
          hs, wired_span_of(transcript, sizeof(transcript)), 1, 0},
      &s_keys_from_client);

  /* server-direction keys are identical whoever derives them */
  for (usz i = 0; i < INITIAL_KEY; i++)
    CHECK(s_keys.key[i] == s_keys_from_client.key[i]);
  /* the two directions differ (client key != server key) */
  int differ = 0;
  for (usz i = 0; i < INITIAL_KEY; i++)
    differ |= (c_keys.key[i] != s_keys.key[i]);
  CHECK(differ);
}

/* 0-RTT keys are deterministic for a PSK+ClientHello, change with the PSK,
 * and differ from the handshake-level keys (distinct label and inputs). */
static void test_schedule_early(void) {
  u8 psk_a[32], psk_b[32];
  for (usz i = 0; i < 32; i++) {
    psk_a[i] = (u8)(i + 7);
    psk_b[i] = (u8)(i + 8);
  }
  const u8 ch[] = "ClientHello";

  initial_keys ka, ka2, kb;
  tls_early_keys(psk_a, ch, sizeof(ch), &ka);
  tls_early_keys(psk_a, ch, sizeof(ch), &ka2);
  tls_early_keys(psk_b, ch, sizeof(ch), &kb);

  for (usz i = 0; i < INITIAL_KEY; i++) CHECK(ka.key[i] == ka2.key[i]);
  int differ = 0;
  for (usz i = 0; i < INITIAL_KEY; i++) differ |= (ka.key[i] != kb.key[i]);
  CHECK(differ); /* different PSK -> different early keys */

  /* early keys differ from handshake keys built from the same bytes as a
   * pseudo-secret (distinct label "c e traffic" vs "c hs traffic") */
  initial_keys hk;
  tls_handshake_keys(
      &(handshake_keys_in){psk_a, wired_span_of(ch, sizeof(ch)), 0, 0}, &hk);
  differ = 0;
  for (usz i = 0; i < INITIAL_KEY; i++) differ |= (ka.key[i] != hk.key[i]);
  CHECK(differ);
}

/* RFC 9369 3.3.1: under v2 the packet-protection expands take the
 * "quicv2 " label prefix, so the key material must differ from v1's; and
 * version 0 (every pre-existing initializer) must stay byte-identical to an
 * explicit VERSION_1 -- the v1-unchanged guard. */
static void test_schedule_v2_labels(void) {
  u8 ecdhe[32], hs[32];
  for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(0x33 + i);
  tls_handshake_secret(ecdhe, hs);
  const u8 tr[] = "ClientHello||ServerHello";

  initial_keys k0, k1, k2;
  tls_handshake_keys(
      &(handshake_keys_in){hs, wired_span_of(tr, sizeof(tr)), 1, 0}, &k0);
  tls_handshake_keys(
      &(handshake_keys_in){hs, wired_span_of(tr, sizeof(tr)), 1, VERSION_1},
      &k1);
  tls_handshake_keys(
      &(handshake_keys_in){hs, wired_span_of(tr, sizeof(tr)), 1, VERSION_2},
      &k2);
  for (usz i = 0; i < INITIAL_KEY; i++) CHECK(k0.key[i] == k1.key[i]);
  for (usz i = 0; i < INITIAL_IV; i++) CHECK(k0.iv[i] == k1.iv[i]);
  for (usz i = 0; i < INITIAL_KEY; i++) CHECK(k0.hp[i] == k1.hp[i]);
  int differ = 0;
  for (usz i = 0; i < INITIAL_KEY; i++) differ |= (k1.key[i] != k2.key[i]);
  CHECK(differ); /* "quicv2 key" != "quic key" expansion */
  differ = 0;
  for (usz i = 0; i < INITIAL_KEY; i++) differ |= (k1.hp[i] != k2.hp[i]);
  CHECK(differ); /* "quicv2 hp" != "quic hp" expansion */
}

void test_schedule(void) {
  test_schedule_agreement();
  test_schedule_directions();
  test_schedule_early();
  test_schedule_v2_labels();
}
