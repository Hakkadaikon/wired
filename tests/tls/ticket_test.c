#include "test.h"

static void fill_key(u8 key[TICKET_KEY_LEN], u8 v) {
  for (usz i = 0; i < TICKET_KEY_LEN; i++) key[i] = v;
}

static ticket sample_ticket(void) {
  ticket t;
  for (usz i = 0; i < TICKET_SECRET_LEN; i++) t.secret[i] = (u8)i;
  t.issued_at     = 1700000000ULL;
  t.lifetime_secs = 86400;
  t.age_add       = 0x12345678;
  return t;
}

/* Sealing then opening with the same key restores the original fields. */
static void test_ticket_roundtrip(void) {
  u8 key[TICKET_KEY_LEN];
  fill_key(key, 0x11);
  ticket in = sample_ticket();
  u8     sealed[TICKET_SEALED_LEN];
  ticket_seal(&in, key, sealed);

  ticket out;
  int    ok = ticket_open(wired_span_of(sealed, TICKET_SEALED_LEN), key, &out);
  CHECK(ok == 1);
  CHECK(out.issued_at == in.issued_at);
  CHECK(out.lifetime_secs == in.lifetime_secs);
  CHECK(out.age_add == in.age_add);
  for (usz i = 0; i < TICKET_SECRET_LEN; i++)
    CHECK(out.secret[i] == in.secret[i]);
}

/* Flipping one byte anywhere in the sealed blob breaks authentication. */
static void test_ticket_tamper_detected(void) {
  u8 key[TICKET_KEY_LEN];
  fill_key(key, 0x22);
  ticket in = sample_ticket();
  u8     sealed[TICKET_SEALED_LEN];
  ticket_seal(&in, key, sealed);
  sealed[TICKET_SEALED_LEN - 1] ^= 0x01;

  ticket out;
  int    ok = ticket_open(wired_span_of(sealed, TICKET_SEALED_LEN), key, &out);
  CHECK(ok == 0);
}

/* Opening with the wrong key fails even on an untampered blob. */
static void test_ticket_wrong_key_rejected(void) {
  u8 key[TICKET_KEY_LEN];
  fill_key(key, 0x33);
  ticket in = sample_ticket();
  u8     sealed[TICKET_SEALED_LEN];
  ticket_seal(&in, key, sealed);

  u8 wrong_key[TICKET_KEY_LEN];
  fill_key(wrong_key, 0x44);
  ticket out;
  int    ok =
      ticket_open(wired_span_of(sealed, TICKET_SEALED_LEN), wrong_key, &out);
  CHECK(ok == 0);
}

/* Each seal draws a fresh random nonce, so two seals of the same ticket
 * under the same key never share their leading nonce bytes. */
static void test_ticket_nonce_varies(void) {
  u8 key[TICKET_KEY_LEN];
  fill_key(key, 0x55);
  ticket in = sample_ticket();
  u8     a[TICKET_SEALED_LEN];
  u8     b[TICKET_SEALED_LEN];
  ticket_seal(&in, key, a);
  ticket_seal(&in, key, b);

  int same = 1;
  for (usz i = 0; i < TICKET_NONCE_LEN; i++)
    if (a[i] != b[i]) same = 0;
  CHECK(!same);
}

/* ticket_open requires in.n == TICKET_SEALED_LEN exactly: neither a
 * truncated nor an over-length blob is accepted, before any AEAD open is
 * attempted (RFC 8446 4.6.1 -- no attacker-controlled length ever drives
 * the memory-copy path). */
static void test_ticket_open_wrong_length_rejected(void) {
  u8 key[TICKET_KEY_LEN];
  fill_key(key, 0x66);
  ticket in = sample_ticket();
  u8     sealed[TICKET_SEALED_LEN];
  ticket_seal(&in, key, sealed);

  ticket out;
  CHECK(
      ticket_open(wired_span_of(sealed, TICKET_SEALED_LEN - 1), key, &out) ==
      0);
  CHECK(
      ticket_open(wired_span_of(sealed, TICKET_SEALED_LEN + 1), key, &out) ==
      0);
  CHECK(ticket_open(wired_span_of(sealed, 0), key, &out) == 0);
}

/* Each ticket seals its own independently-random secret: two tickets built
 * from the same key never share their sealed secret bytes, so compromising
 * one ticket's opened secret does not expose another's. */
static void test_ticket_seal_distinct_secret_per_ticket(void) {
  u8 key[TICKET_KEY_LEN];
  fill_key(key, 0x77);
  ticket a = sample_ticket();
  ticket b = sample_ticket();
  for (usz i = 0; i < TICKET_SECRET_LEN; i++) b.secret[i] = (u8)(0xF0 + i);
  u8 sealed_a[TICKET_SEALED_LEN];
  u8 sealed_b[TICKET_SEALED_LEN];
  ticket_seal(&a, key, sealed_a);
  ticket_seal(&b, key, sealed_b);

  ticket out_a, out_b;
  CHECK(
      ticket_open(wired_span_of(sealed_a, TICKET_SEALED_LEN), key, &out_a) ==
      1);
  CHECK(
      ticket_open(wired_span_of(sealed_b, TICKET_SEALED_LEN), key, &out_b) ==
      1);
  int same = 1;
  for (usz i = 0; i < TICKET_SECRET_LEN; i++)
    if (out_a.secret[i] != out_b.secret[i]) same = 0;
  CHECK(!same);
}

static void test_ticket(void) {
  test_ticket_roundtrip();
  test_ticket_tamper_detected();
  test_ticket_wrong_key_rejected();
  test_ticket_nonce_varies();
  test_ticket_open_wrong_length_rejected();
  test_ticket_seal_distinct_secret_per_ticket();
}
