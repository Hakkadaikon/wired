#include "test.h"

/* 1-RTT app keys: deterministic, the two directions differ, and they differ
 * from the handshake-level keys built from the same bytes (distinct label). */
void test_appkeys(void) {
  u8 ecdhe[32];
  for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(0x10 + i);
  u8 hs[32], ms[32];
  quic_tls_handshake_secret(ecdhe, hs);
  quic_tls_master_secret(hs, ms);
  const u8 transcript[] = "ClientHello||...||Finished";

  quic_initial_keys c, c2, s;
  quic_tls_app_keys(
      &(quic_app_keys_in){ms, quic_span_of(transcript, sizeof(transcript)), 0}, &c);
  quic_tls_app_keys(
      &(quic_app_keys_in){ms, quic_span_of(transcript, sizeof(transcript)), 0}, &c2);
  quic_tls_app_keys(
      &(quic_app_keys_in){ms, quic_span_of(transcript, sizeof(transcript)), 1}, &s);

  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(c.key[i] == c2.key[i]);

  int differ = 0;
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) differ |= (c.key[i] != s.key[i]);
  CHECK(differ); /* client vs server direction differ */

  /* "c ap traffic" keys differ from "c hs traffic" keys over same inputs */
  quic_initial_keys hk;
  quic_tls_handshake_keys(
      &(quic_handshake_keys_in){ms, quic_span_of(transcript, sizeof(transcript)), 0}, &hk);
  differ = 0;
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) differ |= (c.key[i] != hk.key[i]);
  CHECK(differ);
}
