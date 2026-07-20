#include "test.h"

/* The wire token (odcid_len || odcid || HMAC) round-trips: verify succeeds
 * and hands back the embedded ODCID -- the stateless recovery the server
 * needs for the original_destination_connection_id TP (RFC 9000 7.3). */
static void test_retrytoken_wire_roundtrip(void) {
  u8 key[QUIC_RETRYTOKEN_KEY];
  u8 token[QUIC_RETRYTOKEN_WIRE_MAX];
  for (usz i = 0; i < QUIC_RETRYTOKEN_KEY; i++) key[i] = (u8)(i + 1);
  const u8  addr[4]  = {192, 0, 2, 1};
  const u8  odcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  quic_span got      = {0, 0};
  usz       n        = quic_retrytoken_wire_make(
      key, quic_span_of(addr, 4), quic_span_of(odcid, 8), token);
  CHECK(n == 1 + 8 + QUIC_RETRYTOKEN_LEN);
  CHECK(
      quic_retrytoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(token, n), &got) == 1);
  CHECK(got.n == 8);
  for (usz i = 0; i < 8; i++) CHECK(got.p[i] == odcid[i]);
}

/* Tampering any input breaks verification: the HMAC, the embedded ODCID,
 * or the presenting address. */
static void test_retrytoken_wire_tamper_rejected(void) {
  u8 key[QUIC_RETRYTOKEN_KEY];
  u8 token[QUIC_RETRYTOKEN_WIRE_MAX];
  for (usz i = 0; i < QUIC_RETRYTOKEN_KEY; i++) key[i] = (u8)(i + 1);
  const u8  addr[4]  = {192, 0, 2, 1};
  const u8  addr2[4] = {192, 0, 2, 2};
  const u8  odcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  quic_span got;
  usz       n = quic_retrytoken_wire_make(
      key, quic_span_of(addr, 4), quic_span_of(odcid, 8), token);
  token[n - 1] ^= 1; /* HMAC byte */
  CHECK(
      quic_retrytoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(token, n), &got) == 0);
  token[n - 1] ^= 1;
  token[1] ^= 1; /* embedded ODCID byte */
  CHECK(
      quic_retrytoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(token, n), &got) == 0);
  token[1] ^= 1;
  CHECK(
      quic_retrytoken_wire_verify(
          key, quic_span_of(addr2, 4), quic_span_of(token, n), &got) == 0);
}

/* Malformed wire tokens are rejected outright: too short to hold the HMAC,
 * or an odcid_len that overruns the token or the CID cap. */
static void test_retrytoken_wire_malformed_rejected(void) {
  u8        key[QUIC_RETRYTOKEN_KEY] = {0};
  u8        bad[QUIC_RETRYTOKEN_WIRE_MAX];
  const u8  addr[4] = {192, 0, 2, 1};
  quic_span got;
  for (usz i = 0; i < sizeof bad; i++) bad[i] = 0;
  CHECK(
      quic_retrytoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(bad, 10), &got) == 0);
  bad[0] = 21; /* odcid_len over WIRED_MAX_CID_LEN */
  CHECK(
      quic_retrytoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(bad, sizeof bad), &got) ==
      0);
  bad[0] = 8; /* claims 8 but the token is too short to also hold the HMAC */
  CHECK(
      quic_retrytoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(bad, 1 + 8 + 31), &got) ==
      0);
}

/* A token verifies for the address and original DCID it was made for, and
 * not for a different address. */
void test_retrytoken(void) {
  test_retrytoken_wire_roundtrip();
  test_retrytoken_wire_tamper_rejected();
  test_retrytoken_wire_malformed_rejected();
  u8 key[QUIC_RETRYTOKEN_KEY];
  for (usz i = 0; i < QUIC_RETRYTOKEN_KEY; i++) key[i] = (u8)(i + 1);
  const u8 addr[4]  = {192, 0, 2, 1};
  const u8 addr2[4] = {192, 0, 2, 2};
  const u8 odcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};

  quic_retrytoken_in in  = {quic_span_of(addr, 4), quic_span_of(odcid, 8)};
  quic_retrytoken_in in2 = {quic_span_of(addr2, 4), quic_span_of(odcid, 8)};

  u8 token[QUIC_RETRYTOKEN_LEN];
  quic_retrytoken_make(key, &in, token);

  CHECK(quic_retrytoken_verify(key, &in, token) == 1);
  CHECK(quic_retrytoken_verify(key, &in2, token) == 0);
  u8                 odcid2[8] = {1, 2, 3, 4, 5, 6, 7, 9};
  quic_retrytoken_in in_odcid2 = {
      quic_span_of(addr, 4), quic_span_of(odcid2, 8)};
  CHECK(quic_retrytoken_verify(key, &in_odcid2, token) == 0);
  token[0] ^= 0x01;
  CHECK(quic_retrytoken_verify(key, &in, token) == 0);
}
