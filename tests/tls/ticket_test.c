#include "test.h"

static void fill_key(u8 key[QUIC_TICKET_KEY_LEN], u8 v) {
  for (usz i = 0; i < QUIC_TICKET_KEY_LEN; i++) key[i] = v;
}

static quic_ticket sample_ticket(void) {
  quic_ticket t;
  for (usz i = 0; i < QUIC_TICKET_SECRET_LEN; i++) t.secret[i] = (u8)i;
  t.issued_at     = 1700000000ULL;
  t.lifetime_secs = 86400;
  return t;
}

/* Sealing then opening with the same key restores the original fields. */
static void test_ticket_roundtrip(void) {
  u8 key[QUIC_TICKET_KEY_LEN];
  fill_key(key, 0x11);
  quic_ticket in = sample_ticket();
  u8          sealed[QUIC_TICKET_SEALED_LEN];
  quic_ticket_seal(&in, key, sealed);

  quic_ticket out;
  int ok = quic_ticket_open(
      quic_span_of(sealed, QUIC_TICKET_SEALED_LEN), key, &out);
  CHECK(ok == 1);
  CHECK(out.issued_at == in.issued_at);
  CHECK(out.lifetime_secs == in.lifetime_secs);
  for (usz i = 0; i < QUIC_TICKET_SECRET_LEN; i++)
    CHECK(out.secret[i] == in.secret[i]);
}

/* Flipping one byte anywhere in the sealed blob breaks authentication. */
static void test_ticket_tamper_detected(void) {
  u8 key[QUIC_TICKET_KEY_LEN];
  fill_key(key, 0x22);
  quic_ticket in = sample_ticket();
  u8          sealed[QUIC_TICKET_SEALED_LEN];
  quic_ticket_seal(&in, key, sealed);
  sealed[QUIC_TICKET_SEALED_LEN - 1] ^= 0x01;

  quic_ticket out;
  int ok = quic_ticket_open(
      quic_span_of(sealed, QUIC_TICKET_SEALED_LEN), key, &out);
  CHECK(ok == 0);
}

/* Opening with the wrong key fails even on an untampered blob. */
static void test_ticket_wrong_key_rejected(void) {
  u8 key[QUIC_TICKET_KEY_LEN];
  fill_key(key, 0x33);
  quic_ticket in = sample_ticket();
  u8          sealed[QUIC_TICKET_SEALED_LEN];
  quic_ticket_seal(&in, key, sealed);

  u8 wrong_key[QUIC_TICKET_KEY_LEN];
  fill_key(wrong_key, 0x44);
  quic_ticket out;
  int ok = quic_ticket_open(
      quic_span_of(sealed, QUIC_TICKET_SEALED_LEN), wrong_key, &out);
  CHECK(ok == 0);
}

/* Each seal draws a fresh random nonce, so two seals of the same ticket
 * under the same key never share their leading nonce bytes. */
static void test_ticket_nonce_varies(void) {
  u8 key[QUIC_TICKET_KEY_LEN];
  fill_key(key, 0x55);
  quic_ticket in = sample_ticket();
  u8          a[QUIC_TICKET_SEALED_LEN];
  u8          b[QUIC_TICKET_SEALED_LEN];
  quic_ticket_seal(&in, key, a);
  quic_ticket_seal(&in, key, b);

  int same = 1;
  for (usz i = 0; i < QUIC_TICKET_NONCE_LEN; i++)
    if (a[i] != b[i]) same = 0;
  CHECK(!same);
}

static void test_ticket(void) {
  test_ticket_roundtrip();
  test_ticket_tamper_detected();
  test_ticket_wrong_key_rejected();
  test_ticket_nonce_varies();
}
