#include "test.h"

/* 1-RTT app keys: deterministic, the two directions differ, and they differ
 * from the handshake-level keys built from the same bytes (distinct label). */
void test_appkeys(void) {
  u8 ecdhe[32];
  for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(0x10 + i);
  u8 hs[32], ms[32];
  tls_handshake_secret(ecdhe, hs);
  tls_master_secret(hs, ms);
  const u8 transcript[] = "ClientHello||...||Finished";

  initial_keys c, c2, s;
  tls_app_keys(
      &(app_keys_in){ms, wired_span_of(transcript, sizeof(transcript)), 0, 0},
      &c);
  tls_app_keys(
      &(app_keys_in){ms, wired_span_of(transcript, sizeof(transcript)), 0, 0},
      &c2);
  tls_app_keys(
      &(app_keys_in){ms, wired_span_of(transcript, sizeof(transcript)), 1, 0},
      &s);

  for (usz i = 0; i < INITIAL_KEY; i++) CHECK(c.key[i] == c2.key[i]);

  int differ = 0;
  for (usz i = 0; i < INITIAL_KEY; i++) differ |= (c.key[i] != s.key[i]);
  CHECK(differ); /* client vs server direction differ */

  /* "c ap traffic" keys differ from "c hs traffic" keys over same inputs */
  initial_keys hk;
  tls_handshake_keys(
      &(handshake_keys_in){
          ms, wired_span_of(transcript, sizeof(transcript)), 0, 0},
      &hk);
  differ = 0;
  for (usz i = 0; i < INITIAL_KEY; i++) differ |= (c.key[i] != hk.key[i]);
  CHECK(differ);

  /* RFC 9369 3.3.1: v2's "quicv2 " label prefix must change the expanded
   * key; an explicit VERSION_1 must stay byte-identical to the version-0
   * default above (the v1-unchanged guard). */
  initial_keys s1, s2;
  tls_app_keys(
      &(app_keys_in){
          ms, wired_span_of(transcript, sizeof(transcript)), 1, VERSION_1},
      &s1);
  tls_app_keys(
      &(app_keys_in){
          ms, wired_span_of(transcript, sizeof(transcript)), 1, VERSION_2},
      &s2);
  for (usz i = 0; i < INITIAL_KEY; i++) CHECK(s1.key[i] == s.key[i]);
  for (usz i = 0; i < INITIAL_IV; i++) CHECK(s1.iv[i] == s.iv[i]);
  differ = 0;
  for (usz i = 0; i < INITIAL_KEY; i++) differ |= (s2.key[i] != s1.key[i]);
  CHECK(differ);
}
