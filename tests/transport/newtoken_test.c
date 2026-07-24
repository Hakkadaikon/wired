#include "test.h"

static void set_key(u8 key[QUIC_NEWTOKEN_KEY]) {
  for (usz i = 0; i < QUIC_NEWTOKEN_KEY; i++) key[i] = (u8)(i + 1);
}

/* RFC 9000 8.1.3: a freshly made token verifies for the address and time it
 * was made for, and hands back the issued_at it was stamped with. */
static void test_newtoken_wire_roundtrip(void) {
  u8 key[QUIC_NEWTOKEN_KEY];
  set_key(key);
  const u8  addr[4] = {192, 0, 2, 1};
  u8        token[QUIC_NEWTOKEN_WIRE_LEN];
  u64       issued_at;
  quic_span nonce;
  CHECK(quic_newtoken_wire_make(key, quic_span_of(addr, 4), 1000, token) == 1);
  CHECK(
      quic_newtoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(token, sizeof token), 1000,
          &issued_at, &nonce) == 1);
  CHECK(issued_at == 1000);
  CHECK(nonce.n == QUIC_NEWTOKEN_NONCE);
}

/* RFC 9000 8.1.3: "ensure that ... tokens sent in NEW_TOKEN frames are
 * unique". Two tokens made for the same address at the same instant must
 * still differ (via their random nonce), so no two issued tokens collide. */
static void test_newtoken_distinct_per_call(void) {
  u8 key[QUIC_NEWTOKEN_KEY];
  set_key(key);
  const u8 addr[4] = {192, 0, 2, 1};
  u8       t1[QUIC_NEWTOKEN_WIRE_LEN], t2[QUIC_NEWTOKEN_WIRE_LEN];
  CHECK(quic_newtoken_wire_make(key, quic_span_of(addr, 4), 1000, t1) == 1);
  CHECK(quic_newtoken_wire_make(key, quic_span_of(addr, 4), 1000, t2) == 1);
  int differs = 0;
  for (usz i = 0; i < QUIC_NEWTOKEN_WIRE_LEN; i++)
    if (t1[i] != t2[i]) differs = 1;
  CHECK(differs == 1);
}

/* RFC 9000 8.1.3: tokens "SHOULD ensure that ... tokens expire". Exactly at
 * the boundary is still valid; one second past is rejected. */
static void test_newtoken_expiry_boundary(void) {
  u8 key[QUIC_NEWTOKEN_KEY];
  set_key(key);
  const u8  addr[4] = {192, 0, 2, 1};
  u8        token[QUIC_NEWTOKEN_WIRE_LEN];
  u64       issued_at;
  quic_span nonce;
  u64       t0 = 1000;
  CHECK(quic_newtoken_wire_make(key, quic_span_of(addr, 4), t0, token) == 1);

  u64 at_limit = t0 + QUIC_NEWTOKEN_MAX_AGE_SECS;
  CHECK(
      quic_newtoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(token, sizeof token),
          at_limit, &issued_at, &nonce) == 1);

  u64 past_limit = at_limit + 1;
  CHECK(
      quic_newtoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(token, sizeof token),
          past_limit, &issued_at, &nonce) == 0);
}

/* A token presented before its own issued_at (e.g. a manipulated timestamp
 * placed in the future) is rejected too, not just an expired one. */
static void test_newtoken_future_issued_at_rejected(void) {
  u8 key[QUIC_NEWTOKEN_KEY];
  set_key(key);
  const u8  addr[4] = {192, 0, 2, 1};
  u8        token[QUIC_NEWTOKEN_WIRE_LEN];
  u64       issued_at;
  quic_span nonce;
  CHECK(quic_newtoken_wire_make(key, quic_span_of(addr, 4), 5000, token) == 1);
  CHECK(
      quic_newtoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(token, sizeof token), 4999,
          &issued_at, &nonce) == 0);
}

/* RFC 9000 8.1.4: tokens are integrity-protected -- tampering the MAC, the
 * nonce, the issued_at field, or presenting a different address all break
 * verification. */
static void test_newtoken_tamper_rejected(void) {
  u8 key[QUIC_NEWTOKEN_KEY];
  set_key(key);
  const u8  addr[4]  = {192, 0, 2, 1};
  const u8  addr2[4] = {192, 0, 2, 2};
  u8        token[QUIC_NEWTOKEN_WIRE_LEN];
  u64       issued_at;
  quic_span nonce;
  CHECK(quic_newtoken_wire_make(key, quic_span_of(addr, 4), 1000, token) == 1);

  token[QUIC_NEWTOKEN_WIRE_LEN - 1] ^= 1; /* MAC byte */
  CHECK(
      quic_newtoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(token, sizeof token), 1000,
          &issued_at, &nonce) == 0);
  token[QUIC_NEWTOKEN_WIRE_LEN - 1] ^= 1;

  token[8] ^= 1; /* nonce byte */
  CHECK(
      quic_newtoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(token, sizeof token), 1000,
          &issued_at, &nonce) == 0);
  token[8] ^= 1;

  token[0] ^= 1; /* issued_at byte */
  CHECK(
      quic_newtoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(token, sizeof token), 1000,
          &issued_at, &nonce) == 0);
  token[0] ^= 1;

  CHECK(
      quic_newtoken_wire_verify(
          key, quic_span_of(addr2, 4), quic_span_of(token, sizeof token), 1000,
          &issued_at, &nonce) == 0);
}

/* Malformed-length tokens are rejected outright. */
static void test_newtoken_malformed_rejected(void) {
  u8        key[QUIC_NEWTOKEN_KEY]          = {0};
  const u8  addr[4]                         = {192, 0, 2, 1};
  u8        bad[QUIC_NEWTOKEN_WIRE_LEN - 1] = {0};
  u64       issued_at;
  quic_span nonce;
  CHECK(
      quic_newtoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(bad, sizeof bad), 1000,
          &issued_at, &nonce) == 0);
}

/* RFC 9000 8.1.4: replay limiting. Each token's nonce is a fresh, unique
 * identity (uniqueness proven above), so the existing single-use tracker
 * (quic_zerortt_seen, used for 0-RTT ticket replay) applies unchanged: first
 * presentation of a token's nonce succeeds, a second presentation of the
 * same nonce is a replay. */
static void test_newtoken_replay_rejected_via_seen_nonce(void) {
  u8 key[QUIC_NEWTOKEN_KEY];
  set_key(key);
  const u8  addr[4] = {192, 0, 2, 1};
  u8        token[QUIC_NEWTOKEN_WIRE_LEN];
  u64       issued_at;
  quic_span nonce;
  CHECK(quic_newtoken_wire_make(key, quic_span_of(addr, 4), 1000, token) == 1);
  CHECK(
      quic_newtoken_wire_verify(
          key, quic_span_of(addr, 4), quic_span_of(token, sizeof token), 1000,
          &issued_at, &nonce) == 1);

  quic_zerortt_seen seen;
  quic_zerortt_seen_init(&seen);
  CHECK(quic_zerortt_seen_check(&seen, nonce) == 1); /* first use */
  CHECK(quic_zerortt_seen_check(&seen, nonce) == 0); /* replay */
}

void test_newtoken(void) {
  test_newtoken_wire_roundtrip();
  test_newtoken_distinct_per_call();
  test_newtoken_expiry_boundary();
  test_newtoken_future_issued_at_rejected();
  test_newtoken_tamper_rejected();
  test_newtoken_malformed_rejected();
  test_newtoken_replay_rejected_via_seen_nonce();
}
