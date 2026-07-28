#include "app/moqt/kvp/moqkvp.h"

#include "test.h"

/* @file
 * draft-ietf-moq-transport-19 1.4.3 Key-Value-Pair codec tests. Golden byte
 * sequences are hand-derived from the section's format (MOQT varint per
 * 1.4.1) and shared with the TS client's pinned vectors.
 */

/* TEST 1: even Type, varint value. 00 25 -> {Type 0, num 37}. */
static void test_moqkvp_take_even_num(void) {
  const u8    in[] = {0x00, 0x25};
  usz         off  = 0;
  u64         prev = 0;
  quic_moqkvp kv;

  CHECK(
      quic_moqkvp_take(quic_span_of(in, sizeof in), &off, &prev, &kv) ==
      QUIC_MOQKVP_OK);
  CHECK(kv.type == 0);
  CHECK(!kv.is_raw);
  CHECK(kv.num == 37);
  CHECK(off == 2);
  CHECK(prev == 0);
}

/* TEST 2: odd Type, Length + raw bytes. 01 03 61 62 63 -> {Type 1, "abc"}. */
static void test_moqkvp_take_odd_raw(void) {
  const u8    in[] = {0x01, 0x03, 0x61, 0x62, 0x63};
  usz         off  = 0;
  u64         prev = 0;
  quic_moqkvp kv;

  CHECK(
      quic_moqkvp_take(quic_span_of(in, sizeof in), &off, &prev, &kv) ==
      QUIC_MOQKVP_OK);
  CHECK(kv.type == 1);
  CHECK(kv.is_raw);
  CHECK(kv.raw.n == 3);
  CHECK(kv.raw.p[0] == 0x61 && kv.raw.p[1] == 0x62 && kv.raw.p[2] == 0x63);
  CHECK(off == 5);
  CHECK(prev == 1);
}

/* TEST 3: Delta accumulates across pairs. 02 05 03 01 aa ->
 * {Type 2, num 5} then {Type 2+3=5, raw [aa]}. */
static void test_moqkvp_take_delta_accumulates(void) {
  const u8    in[] = {0x02, 0x05, 0x03, 0x01, 0xAA};
  usz         off  = 0;
  u64         prev = 0;
  quic_moqkvp kv;

  CHECK(
      quic_moqkvp_take(quic_span_of(in, sizeof in), &off, &prev, &kv) ==
      QUIC_MOQKVP_OK);
  CHECK(kv.type == 2 && !kv.is_raw && kv.num == 5);
  CHECK(
      quic_moqkvp_take(quic_span_of(in, sizeof in), &off, &prev, &kv) ==
      QUIC_MOQKVP_OK);
  CHECK(kv.type == 5);
  CHECK(kv.is_raw);
  CHECK(kv.raw.n == 1 && kv.raw.p[0] == 0xAA);
  CHECK(off == sizeof in);
  CHECK(prev == 5);
}

/* TEST 4: non-minimal Delta varint is legal (1.4.1: any representable
 * length is valid). 80 00 25 -> Delta 0 in 2 bytes -> {Type 0, num 37}. */
static void test_moqkvp_take_nonminimal_delta(void) {
  const u8    in[] = {0x80, 0x00, 0x25};
  usz         off  = 0;
  u64         prev = 0;
  quic_moqkvp kv;

  CHECK(
      quic_moqkvp_take(quic_span_of(in, sizeof in), &off, &prev, &kv) ==
      QUIC_MOQKVP_OK);
  CHECK(kv.type == 0 && kv.num == 37);
  CHECK(off == 3);
}

/* TEST 5: even Type whose value varint is non-minimal is also accepted.
 * 00 80 25 -> value 37 in 2 bytes -> {Type 0, num 37}. */
static void test_moqkvp_take_nonminimal_even_value(void) {
  const u8    in[] = {0x00, 0x80, 0x25};
  usz         off  = 0;
  u64         prev = 0;
  quic_moqkvp kv;

  CHECK(
      quic_moqkvp_take(quic_span_of(in, sizeof in), &off, &prev, &kv) ==
      QUIC_MOQKVP_OK);
  CHECK(kv.type == 0 && kv.num == 37);
  CHECK(off == 3);
}

/* TEST 6: cumulative Type past 2^64-1 is a violation; exactly 2^64-1 is
 * still accepted (boundary). Cursor and prev stay unmodified on error. */
static void test_moqkvp_take_type_overflow(void) {
  const u8    d1[] = {0x01, 0x00}; /* Delta 1 -> overflow */
  const u8    d0[] = {0x00, 0x00}; /* Delta 0, Length 0 (Type odd) */
  usz         off  = 0;
  u64         prev = (u64)-1;
  quic_moqkvp kv;

  CHECK(
      quic_moqkvp_take(quic_span_of(d1, sizeof d1), &off, &prev, &kv) ==
      QUIC_MOQKVP_VIOLATION);
  CHECK(off == 0 && prev == (u64)-1);

  CHECK(
      quic_moqkvp_take(quic_span_of(d0, sizeof d0), &off, &prev, &kv) ==
      QUIC_MOQKVP_OK);
  CHECK(kv.type == (u64)-1 && kv.is_raw && kv.raw.n == 0);
}

/* Shared backing store for the Length boundary pair. 1.4.3 caps Length at
 * 2^16-1, so the accept case carries QUIC_MOQKVP_MAX_LEN real bytes and the
 * reject case one more; both use the production limit constant. */
static u8 moqkvp_len_buf[3 + QUIC_MOQKVP_MAX_LEN + 1];

/* TEST 7: Length 65535 (c0 ff ff, 3-byte varint) with full data: accepted. */
static void test_moqkvp_take_len_65535_accepted(void) {
  usz         off  = 0;
  u64         prev = 0;
  quic_moqkvp kv;

  moqkvp_len_buf[0] = 0x01; /* Delta 1 -> odd Type 1 */
  moqkvp_len_buf[1] = 0xC0; /* Length 65535 as 3-byte varint */
  moqkvp_len_buf[2] = 0xFF;
  moqkvp_len_buf[3] = 0xFF;
  for (usz i = 0; i < QUIC_MOQKVP_MAX_LEN; i++) moqkvp_len_buf[4 + i] = (u8)i;

  CHECK(
      quic_moqkvp_take(
          quic_span_of(moqkvp_len_buf, 4 + QUIC_MOQKVP_MAX_LEN), &off, &prev,
          &kv) == QUIC_MOQKVP_OK);
  CHECK(kv.type == 1 && kv.is_raw);
  CHECK(kv.raw.n == QUIC_MOQKVP_MAX_LEN);
  CHECK(kv.raw.p[QUIC_MOQKVP_MAX_LEN - 1] == (u8)(QUIC_MOQKVP_MAX_LEN - 1));
  CHECK(off == 4 + QUIC_MOQKVP_MAX_LEN);
}

/* TEST 8: Length 65536 (c1 00 00) with the data actually present: still a
 * violation -- the limit check, not a truncation check, must fire. */
static void test_moqkvp_take_len_65536_violation(void) {
  usz         off  = 0;
  u64         prev = 0;
  quic_moqkvp kv;

  moqkvp_len_buf[0] = 0x01; /* Delta 1 -> odd Type 1 */
  moqkvp_len_buf[1] = 0xC1; /* Length 65536 as 3-byte varint */
  moqkvp_len_buf[2] = 0x00;
  moqkvp_len_buf[3] = 0x00;

  CHECK(
      quic_moqkvp_take(
          quic_span_of(moqkvp_len_buf, sizeof moqkvp_len_buf), &off, &prev,
          &kv) == QUIC_MOQKVP_VIOLATION);
  CHECK(off == 0 && prev == 0);
}

/* TEST 9: raw value cut short of its declared Length -> insufficient
 * (distinct from violation; the caller picks the close code). */
static void test_moqkvp_take_truncated_insufficient(void) {
  const u8    in[] = {0x01, 0x03, 0x61};
  usz         off  = 0;
  u64         prev = 0;
  quic_moqkvp kv;

  CHECK(
      quic_moqkvp_take(quic_span_of(in, sizeof in), &off, &prev, &kv) ==
      QUIC_MOQKVP_INSUFFICIENT);
  CHECK(off == 0 && prev == 0);

  /* empty input: even the Delta varint is missing */
  CHECK(
      quic_moqkvp_take(quic_span_of(0, 0), &off, &prev, &kv) ==
      QUIC_MOQKVP_INSUFFICIENT);
}

/* TEST 10: encode -> decode round-trip with Delta accumulation; the encoded
 * bytes pin to the TEST 3 golden 02 05 03 01 aa. */
static void test_moqkvp_roundtrip(void) {
  const u8    golden[] = {0x02, 0x05, 0x03, 0x01, 0xAA};
  u8          buf[16];
  const u8    aa   = 0xAA;
  quic_moqkvp even = {2, 0, 5, {0, 0}};
  quic_moqkvp odd  = {5, 1, 0, {&aa, 1}};
  usz         off  = 0;
  u64         prev = 0;

  CHECK(quic_moqkvp_put(quic_mspan_of(buf, sizeof buf), &off, &prev, &even));
  CHECK(quic_moqkvp_put(quic_mspan_of(buf, sizeof buf), &off, &prev, &odd));
  CHECK(off == sizeof golden);
  CHECK(prev == 5);
  for (usz i = 0; i < sizeof golden; i++) CHECK(buf[i] == golden[i]);
}

/* TEST 11: put rejects a Type below the running Type (Delta would be
 * negative), an over-limit raw length, and a full buffer -- leaving the
 * cursor and prev untouched each time. */
static void test_moqkvp_put_rejects(void) {
  u8          buf[8];
  quic_moqkvp back     = {1, 0, 0, {0, 0}};
  quic_moqkvp too_long = {3, 1, 0, {moqkvp_len_buf, QUIC_MOQKVP_MAX_LEN + 1}};
  quic_moqkvp ok       = {2, 0, 7, {0, 0}};
  usz         off      = 0;
  u64         prev     = 2;

  CHECK(!quic_moqkvp_put(quic_mspan_of(buf, sizeof buf), &off, &prev, &back));
  CHECK(
      !quic_moqkvp_put(quic_mspan_of(buf, sizeof buf), &off, &prev, &too_long));
  CHECK(!quic_moqkvp_put(quic_mspan_of(buf, 1), &off, &prev, &ok));
  CHECK(off == 0 && prev == 2);
}

void test_moqkvp(void) {
  test_moqkvp_take_even_num();
  test_moqkvp_take_odd_raw();
  test_moqkvp_take_delta_accumulates();
  test_moqkvp_take_nonminimal_delta();
  test_moqkvp_take_nonminimal_even_value();
  test_moqkvp_take_type_overflow();
  test_moqkvp_take_len_65535_accepted();
  test_moqkvp_take_len_65536_violation();
  test_moqkvp_take_truncated_insufficient();
  test_moqkvp_roundtrip();
  test_moqkvp_put_rejects();
}
