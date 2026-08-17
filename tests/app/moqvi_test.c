#include "app/moqt/vi/moqvi.h"

#include "test.h"

/* @file
 * draft-ietf-moq-transport-19 1.4.1 variable-length integer tests, pinned to
 * the draft's own example encodings (leading-1-count length, 1..9 bytes,
 * network byte order, non-minimal encodings accepted).
 */

/* One decode golden: wire bytes -> expected value and consumed length. */
typedef struct {
  const u8* p;
  usz       n;
  u64       v;
} moqvi_dec_vec;

/* One encode golden: value -> expected minimal wire bytes. */
typedef struct {
  u64       v;
  const u8* p;
  usz       n;
} moqvi_enc_vec;

static void check_decode(const moqvi_dec_vec* g) {
  u64 out = 0;
  usz off = 0;
  CHECK(quic_moqvi_take(wired_span_of(g->p, g->n), &off, &out));
  CHECK(out == g->v);
  CHECK(off == g->n);
}

/* TEST 1: the draft's example table (1.4.1), all 8 rows, including the
 * non-minimal 0x8025 and the 9-byte maximum. */
static void test_moqvi_decode_official_examples(void) {
  static const u8 ex1[] = {0x25};
  static const u8 ex2[] = {0x80, 0x25};
  static const u8 ex3[] = {0xbb, 0xbd};
  static const u8 ex4[] = {0xed, 0x7f, 0x3e, 0x7d};
  static const u8 ex5[] = {0xfa, 0xa1, 0xa0, 0xe4, 0x03, 0xd8};
  static const u8 ex6[] = {0xfc, 0x89, 0x98, 0xab, 0xc6, 0x6b, 0xc0};
  static const u8 ex7[] = {0xfe, 0xfa, 0x31, 0x8f, 0xa8, 0xe3, 0xca, 0x11};
  static const u8 ex8[] = {0xff, 0xff, 0xff, 0xff, 0xff,
                           0xff, 0xff, 0xff, 0xff};
  static const moqvi_dec_vec g[8] = {
      {ex1, 1, 37},
      {ex2, 2, 37},
      {ex3, 2, 15293},
      {ex4, 4, 226442877},
      {ex5, 6, 2893212287960ULL},
      {ex6, 7, 151288809941952ULL},
      {ex7, 8, 70423237261249041ULL},
      {ex8, 9, 0xFFFFFFFFFFFFFFFFULL},
  };
  for (usz i = 0; i < 8; i++) check_decode(&g[i]);
}

/* TEST 2: value 0 in all 9 encoding lengths is accepted (non-minimal
 * encodings are valid). */
static void test_moqvi_decode_zero_all_lengths(void) {
  static const u8 prefix[9] = {0x00, 0x80, 0xC0, 0xE0, 0xF0,
                               0xF8, 0xFC, 0xFE, 0xFF};
  for (usz k = 1; k <= 9; k++) {
    u8  buf[9] = {0};
    u64 out    = 1;
    buf[0]     = prefix[k - 1];
    CHECK(quic_moqvi_decode(buf, k, &out) == k);
    CHECK(out == 0);
  }
}

/* TEST 3: 37 padded out to the full 9-byte form. */
static void test_moqvi_decode_nine_byte_padded(void) {
  static const u8            buf[9] = {0xFF, 0, 0, 0, 0, 0, 0, 0, 0x25};
  static const moqvi_dec_vec g      = {buf, 9, 37};
  check_decode(&g);
}

static void check_encode(const moqvi_enc_vec* g) {
  u8  buf[9] = {0};
  usz off    = 0;
  CHECK(quic_moqvi_len(g->v) == g->n);
  CHECK(quic_moqvi_put(wired_mspan_of(buf, sizeof buf), &off, g->v));
  CHECK(off == g->n);
  for (usz i = 0; i < g->n; i++) CHECK(buf[i] == g->p[i]);
}

/* TEST 4: minimal-length encode of the draft's example values (the minimal
 * 7 rows plus the 9-byte maximum). */
static void test_moqvi_encode_official_examples(void) {
  static const u8 ex1[] = {0x25};
  static const u8 ex3[] = {0xbb, 0xbd};
  static const u8 ex4[] = {0xed, 0x7f, 0x3e, 0x7d};
  static const u8 ex5[] = {0xfa, 0xa1, 0xa0, 0xe4, 0x03, 0xd8};
  static const u8 ex6[] = {0xfc, 0x89, 0x98, 0xab, 0xc6, 0x6b, 0xc0};
  static const u8 ex7[] = {0xfe, 0xfa, 0x31, 0x8f, 0xa8, 0xe3, 0xca, 0x11};
  static const u8 ex8[] = {0xff, 0xff, 0xff, 0xff, 0xff,
                           0xff, 0xff, 0xff, 0xff};
  static const moqvi_enc_vec g[7] = {
      {37, ex1, 1},
      {15293, ex3, 2},
      {226442877, ex4, 4},
      {2893212287960ULL, ex5, 6},
      {151288809941952ULL, ex6, 7},
      {70423237261249041ULL, ex7, 8},
      {0xFFFFFFFFFFFFFFFFULL, ex8, 9},
  };
  for (usz i = 0; i < 7; i++) check_encode(&g[i]);
}

/* TEST 5: encode length steps up exactly at each capacity boundary. */
static void test_moqvi_encode_boundaries(void) {
  static const u8 b127[]   = {0x7f};
  static const u8 b128[]   = {0x80, 0x80};
  static const u8 b16383[] = {0xbf, 0xff};
  static const u8 b16384[] = {0xc0, 0x40, 0x00};
  static const u8 b56max[] = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  static const u8 b56one[] = {0xff, 0x01, 0, 0, 0, 0, 0, 0, 0};
  static const moqvi_enc_vec g[6] = {
      {127, b127, 1},
      {128, b128, 2},
      {16383, b16383, 2},
      {16384, b16384, 3},
      {0xFFFFFFFFFFFFFFULL, b56max, 8},
      {0x100000000000000ULL, b56one, 9},
  };
  for (usz i = 0; i < 6; i++) check_encode(&g[i]);
}

static void check_truncated(const u8* p, usz n) {
  u64 out = 0;
  usz off = 0;
  CHECK(quic_moqvi_decode(p, n, &out) == 0);
  CHECK(!quic_moqvi_take(wired_span_of(p, n), &off, &out));
  CHECK(off == 0);
}

/* TEST 6: truncated input (needed length > available bytes) fails without
 * reading past the end. */
static void test_moqvi_decode_truncated(void) {
  static const u8 t1[] = {0x80};
  static const u8 t2[] = {0xed, 0x7f, 0x3e};
  static const u8 t3[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  u64             out  = 0;
  check_truncated(t1, 1);
  check_truncated(t2, 3);
  check_truncated(t3, 8);
  CHECK(quic_moqvi_decode(t1, 0, &out) == 0);
}

/* TEST 7: put -> take round-trip of representative values, back to back in
 * one buffer. */
static void test_moqvi_roundtrip(void) {
  static const u64 vals[7] = {
      0, 1, 127, 128, 2097151, 0xFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
  u8  buf[64];
  usz off = 0;
  usz at  = 0;
  for (usz i = 0; i < 7; i++)
    CHECK(quic_moqvi_put(wired_mspan_of(buf, sizeof buf), &off, vals[i]));
  for (usz i = 0; i < 7; i++) {
    u64 out = 0;
    CHECK(quic_moqvi_take(wired_span_of(buf, off), &at, &out));
    CHECK(out == vals[i]);
  }
  CHECK(at == off);
}

/* TEST 8: trailing bytes after a complete integer change nothing -- decode
 * consumes exactly the encoded length. */
static void test_moqvi_decode_ignores_trailing(void) {
  static const u8 buf[] = {0xbb, 0xbd, 0xAA, 0xBB};
  u64             out   = 0;
  usz             off   = 0;
  CHECK(quic_moqvi_take(wired_span_of(buf, sizeof buf), &off, &out));
  CHECK(out == 15293);
  CHECK(off == 2);
}

/* TEST 9: put fails cleanly when the value does not fit the remaining
 * capacity, leaving the cursor unchanged. */
static void test_moqvi_put_too_small(void) {
  u8  buf[2];
  usz off = 0;
  CHECK(!quic_moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 16384));
  CHECK(off == 0);
  CHECK(quic_moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 16383));
  CHECK(off == 2);
  CHECK(!quic_moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0));
}

void test_moqvi(void) {
  test_moqvi_decode_official_examples();
  test_moqvi_decode_zero_all_lengths();
  test_moqvi_decode_nine_byte_padded();
  test_moqvi_encode_official_examples();
  test_moqvi_encode_boundaries();
  test_moqvi_decode_truncated();
  test_moqvi_roundtrip();
  test_moqvi_decode_ignores_trailing();
  test_moqvi_put_too_small();
}
