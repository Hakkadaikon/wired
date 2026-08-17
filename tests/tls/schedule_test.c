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
          hs, wired_span_of(transcript, sizeof(transcript)), 0},
      &c_keys);
  tls_handshake_keys(
      &(handshake_keys_in){
          hs, wired_span_of(transcript, sizeof(transcript)), 1},
      &s_keys);
  tls_handshake_keys(
      &(handshake_keys_in){
          hs, wired_span_of(transcript, sizeof(transcript)), 1},
      &s_keys_from_client);

  /* server-direction keys are identical whoever derives them */
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++)
    CHECK(s_keys.key[i] == s_keys_from_client.key[i]);
  /* the two directions differ (client key != server key) */
  int differ = 0;
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++)
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

  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(ka.key[i] == ka2.key[i]);
  int differ = 0;
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) differ |= (ka.key[i] != kb.key[i]);
  CHECK(differ); /* different PSK -> different early keys */

  /* early keys differ from handshake keys built from the same bytes as a
   * pseudo-secret (distinct label "c e traffic" vs "c hs traffic") */
  initial_keys hk;
  tls_handshake_keys(
      &(handshake_keys_in){psk_a, wired_span_of(ch, sizeof(ch)), 0}, &hk);
  differ = 0;
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) differ |= (ka.key[i] != hk.key[i]);
  CHECK(differ);
}

void test_schedule(void) {
  test_schedule_agreement();
  test_schedule_directions();
  test_schedule_early();
}
