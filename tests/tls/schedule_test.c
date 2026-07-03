#include "test.h"

/* Both peers feed the same ECDHE secret into the schedule and arrive at the
 * same handshake secret (this is what lets them agree on traffic keys). */
static void test_schedule_agreement(void) {
  u8 ecdhe[32];
  for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(i + 1);
  u8 hs_a[32], hs_b[32];
  quic_tls_handshake_secret(ecdhe, hs_a);
  quic_tls_handshake_secret(ecdhe, hs_b);
  for (usz i = 0; i < 32; i++) CHECK(hs_a[i] == hs_b[i]); /* deterministic */
}

/* Client and server derive distinct directions, but each side computing the
 * peer's direction matches: client's "s hs traffic" == server's own keys. */
static void test_schedule_directions(void) {
  u8 ecdhe[32], hs[32];
  for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(0xA0 + i);
  quic_tls_handshake_secret(ecdhe, hs);
  const u8 transcript[] = "ClientHello||ServerHello";

  quic_initial_keys c_keys, s_keys, s_keys_from_client;
  quic_tls_handshake_keys(
      &(quic_handshake_keys_in){hs, quic_span_of(transcript, sizeof(transcript)), 0}, &c_keys);
  quic_tls_handshake_keys(
      &(quic_handshake_keys_in){hs, quic_span_of(transcript, sizeof(transcript)), 1}, &s_keys);
  quic_tls_handshake_keys(
      &(quic_handshake_keys_in){hs, quic_span_of(transcript, sizeof(transcript)), 1}, &s_keys_from_client);

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

  quic_initial_keys ka, ka2, kb;
  quic_tls_early_keys(psk_a, ch, sizeof(ch), &ka);
  quic_tls_early_keys(psk_a, ch, sizeof(ch), &ka2);
  quic_tls_early_keys(psk_b, ch, sizeof(ch), &kb);

  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(ka.key[i] == ka2.key[i]);
  int differ = 0;
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) differ |= (ka.key[i] != kb.key[i]);
  CHECK(differ); /* different PSK -> different early keys */

  /* early keys differ from handshake keys built from the same bytes as a
   * pseudo-secret (distinct label "c e traffic" vs "c hs traffic") */
  quic_initial_keys hk;
  quic_tls_handshake_keys(
      &(quic_handshake_keys_in){psk_a, quic_span_of(ch, sizeof(ch)), 0}, &hk);
  differ = 0;
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) differ |= (ka.key[i] != hk.key[i]);
  CHECK(differ);
}

void test_schedule(void) {
  test_schedule_agreement();
  test_schedule_directions();
  test_schedule_early();
}
