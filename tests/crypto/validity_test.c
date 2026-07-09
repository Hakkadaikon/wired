#include "crypto/pki/encoding/x509/validity.h"

#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"
#include "x509_golden.h"

/* The golden cert is valid 20260628030430 .. 20270628030430 (UTCTime). */
#define NB 20260628030430ULL
#define NA 20270628030430ULL

static void test_validity_golden(void) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_x509_golden, sizeof(quic_x509_golden)), &c) == 1);

  /* exactly notBefore and notAfter are inclusive */
  CHECK(quic_x509_validity_ok(c.tbs, NB) == 1);
  CHECK(quic_x509_validity_ok(c.tbs, NA) == 1);
  /* a moment inside the window */
  CHECK(quic_x509_validity_ok(c.tbs, 20261225000000ULL) == 1);
  /* one second before notBefore: expired/not-yet-valid */
  CHECK(quic_x509_validity_ok(c.tbs, NB - 1) == 0);
  /* one second after notAfter: expired */
  CHECK(quic_x509_validity_ok(c.tbs, NA + 1) == 0);
}

static void test_validity_malformed(void) {
  /* tbs too short to read a SEQUENCE header */
  CHECK(quic_x509_validity_ok(quic_span_of(quic_x509_golden + 4, 3), NB) == 0);
  /* tbs SEQUENCE without enough elements to reach validity */
  const u8 tbs[] = {0x30, 0x03, 0x02, 0x01, 0x02};
  CHECK(quic_x509_validity_ok(quic_span_of(tbs, sizeof(tbs)), NB) == 0);
}

/* 1 if a[0..13) equals the NUL-terminated ASCII literal want. */
static int utctime_eq(const u8 a[13], const char* want) {
  for (usz i = 0; i < 13; i++)
    if (a[i] != (u8)want[i]) return 0;
  return 1;
}

/* RFC 5280 4.1.2.5.1: known YYYYMMDDHHMMSS -> exact UTCTime bytes. */
static void test_utctime_encode_known(void) {
  u8 out[13];
  quic_x509_utctime_encode(NB, out);
  CHECK(utctime_eq(out, "260628030430Z"));
}

/* Century wraps at 2000/1900 per RFC 5280 4.1.2.5.1; only the low 2 digits of
 * the year are ever encoded, so 1999 and 2099 collide on "99" -- that
 * ambiguity is inherent to UTCTime, not this function's bug. */
static void test_utctime_encode_year_boundary(void) {
  u8 out[13];
  quic_x509_utctime_encode(20000101000000ULL, out);
  CHECK(utctime_eq(out, "000101000000Z"));
  quic_x509_utctime_encode(20491231235959ULL, out);
  CHECK(utctime_eq(out, "491231235959Z"));
}

/* Append n bytes from src onto dst at *off, advancing *off. */
static void vt_append(u8* dst, usz* off, const u8* src, usz n) {
  for (usz j = 0; j < n; j++) dst[(*off)++] = src[j];
}

/* tbs = SEQUENCE { serial, sigAlg, issuer, Validity SEQUENCE { notBefore
 * UTCTime, notAfter UTCTime } } -- only what tbs_to_validity needs to reach
 * the Validity element (no [0] version, then VALIDITY_SKIP = 3 elements:
 * serial/sigAlg/issuer). Returns the written length. */
static usz build_tbs_with_validity(
    const u8 nb[13], const u8 na[13], u8 tbs[70]) {
  static const u8 head[] = {
      0x02, 0x01, 0x01, /* serial: INTEGER 1 */
      0x02, 0x01, 0x00, /* sigAlg placeholder: INTEGER 0 */
      0x02, 0x01, 0x00, /* issuer placeholder: INTEGER 0 */
      0x30, 30,         /* Validity SEQUENCE, len = 2*(2+13) */
  };
  static const u8 utctime_tl[] = {0x17, 13};
  u8              body[64];
  usz             n = 0;
  vt_append(body, &n, head, sizeof(head));
  vt_append(body, &n, utctime_tl, sizeof(utctime_tl));
  vt_append(body, &n, nb, 13);
  vt_append(body, &n, utctime_tl, sizeof(utctime_tl));
  vt_append(body, &n, na, 13);

  usz m    = 0;
  tbs[m++] = 0x30;
  tbs[m++] = (u8)n; /* outer SEQUENCE wrapping quic_der_seq expects */
  vt_append(tbs, &m, body, n);
  return m;
}

/* Encoding a window [notBefore, notAfter) into a synthetic tbs and reading it
 * back through quic_x509_validity_ok proves the encoder and the existing
 * decoder agree on the same wire bytes for a spread of dates, not just the
 * one golden fixture above. */
static void test_utctime_encode_roundtrip(void) {
  static const u64 samples[] = {
      20260628030430ULL, 20200101000000ULL, 20301231235959ULL,
      20260101120000ULL};
  for (usz i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
    u8 nb[13], na[13], tbs[70];
    quic_x509_utctime_encode(samples[i], nb);
    quic_x509_utctime_encode(samples[i] + 1, na);
    usz m = build_tbs_with_validity(nb, na, tbs);

    CHECK(quic_x509_validity_ok(quic_span_of(tbs, m), samples[i]) == 1);
    CHECK(quic_x509_validity_ok(quic_span_of(tbs, m), samples[i] + 1) == 1);
    CHECK(quic_x509_validity_ok(quic_span_of(tbs, m), samples[i] - 1) == 0);
  }
}

void test_validity(void) {
  test_validity_golden();
  test_validity_malformed();
  test_utctime_encode_known();
  test_utctime_encode_year_boundary();
  test_utctime_encode_roundtrip();
}
