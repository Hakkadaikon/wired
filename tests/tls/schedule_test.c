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

/* RFC 8446 7.1: Derive-Secret reports an HKDF-Expand-Label failure (a
 * label past the 64-byte wire limit) instead of leaving out uninitialized
 * -- the result is 0 and out is all zero, and tls_exporter carries that 0
 * through rather than exporting from garbage. */
static void test_tls_derive_secret_propagates_expand_failure(void) {
  u8               secret[HKDF_PRK], out[HKDF_PRK], okm[8];
  u8               label[65];
  derive_secret_in in;
  for (usz i = 0; i < sizeof(secret); i++) secret[i] = (u8)(0x30 + i);
  for (usz i = 0; i < sizeof(out); i++) out[i] = 0xaa;
  for (usz i = 0; i < sizeof(label); i++) label[i] = 'x';
  in.secret   = secret;
  in.label    = wired_span_of(label, 12);
  in.messages = wired_span_of(label, 0);
  CHECK(tls_derive_secret(&in, out) == 1);
  in.label = wired_span_of(label, sizeof(label));
  CHECK(tls_derive_secret(&in, out) == 0);
  for (usz i = 0; i < sizeof(out); i++) CHECK(out[i] == 0);
  CHECK(
      tls_exporter(
          secret, wired_span_of(label, sizeof(label)), wired_span_of(0, 0),
          wired_mspan_of(okm, sizeof(okm))) == 0);
}

/* RFC 8446 E.1.15 / 7.5: TLS-Exporter output is computationally
 * independent across distinct labels/contexts (each re-derives its own
 * Derive-Secret(...,label,"") before HKDF-Expand-Label), and matches the
 * full HKDF_PRK width. */
static void test_exporter_distinct_labels_independent_output(void) {
  u8         secret[HKDF_PRK];
  u8         okm_a[HKDF_PRK], okm_b[HKDF_PRK], okm_c[HKDF_PRK];
  const char label_a[] = "label a", label_b[] = "label b";
  const u8   ctx1[] = "context-1", ctx2[] = "context-2";
  for (usz i = 0; i < sizeof(secret); i++) secret[i] = (u8)(0x50 + i);

  CHECK(
      tls_exporter(
          secret, wired_span_of((const u8*)label_a, 7),
          wired_span_of(ctx1, sizeof(ctx1)),
          wired_mspan_of(okm_a, sizeof(okm_a))) == 1);
  CHECK(
      tls_exporter(
          secret, wired_span_of((const u8*)label_b, 7),
          wired_span_of(ctx1, sizeof(ctx1)),
          wired_mspan_of(okm_b, sizeof(okm_b))) == 1);
  CHECK(
      tls_exporter(
          secret, wired_span_of((const u8*)label_a, 7),
          wired_span_of(ctx2, sizeof(ctx2)),
          wired_mspan_of(okm_c, sizeof(okm_c))) == 1);

  int differ_label = 0, differ_ctx = 0;
  for (usz i = 0; i < HKDF_PRK; i++) {
    differ_label |= (okm_a[i] != okm_b[i]);
    differ_ctx |= (okm_a[i] != okm_c[i]);
  }
  CHECK(differ_label); /* distinct label -> independent output */
  CHECK(differ_ctx);   /* distinct context -> independent output */
}

/* RFC 9001 9.4: hp is derived under a distinct label ("hp") from the AEAD
 * packet-protection key ("key"), so the two must never coincide. */
static void test_schedule_hp_key_distinct_from_packet_key(void) {
  u8 ecdhe[32], hs[32];
  for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(0x60 + i);
  tls_handshake_secret(ecdhe, hs);
  const u8 tr[] = "ClientHello||ServerHello";

  initial_keys k;
  tls_handshake_keys(
      &(handshake_keys_in){hs, wired_span_of(tr, sizeof(tr)), 0, 0}, &k);
  int differ = 0;
  for (usz i = 0; i < INITIAL_KEY; i++) differ |= (k.key[i] != k.hp[i]);
  CHECK(differ);
}

void test_schedule(void) {
  test_tls_derive_secret_propagates_expand_failure();
  test_schedule_agreement();
  test_schedule_directions();
  test_schedule_early();
  test_schedule_v2_labels();
  test_exporter_distinct_labels_independent_output();
  test_schedule_hp_key_distinct_from_packet_key();
}
