#include "crypto/pki/encoding/x509/validity.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/x509/x509.h"

/* RFC 5280 4.1. Before validity sit serialNumber, signature and issuer. */
#define VALIDITY_SKIP 3

#define DER_UTCTIME 0x17
#define DER_GENTIME 0x18

static int is_digit(u8 c) { return c >= '0' && c <= '9'; }

/* Parse n ASCII digits into a number. 1 ok, 0 if any octet is not a digit. */
static int digits(const u8 *p, usz n, u64 *out) {
  u64 v = 0;
  for (usz i = 0; i < n; i++) {
    if (!is_digit(p[i])) return 0;
    v = v * 10 + (u64)(p[i] - '0');
  }
  *out = v;
  return 1;
}

/* Z-terminated string of the expected length. */
static int zterm(quic_span v, usz want) {
  return v.n == want && v.p[want - 1] == 'Z';
}

/* RFC 5280 4.1.2.5.1. Century for a 2-digit year: <50 => 2000s, else 1900s. */
static u64 century(u64 yy) { return yy < 50 ? 2000 : 1900; }

/* UTCTime YYMMDDHHMMSS digits into a full YYYYMMDDHHMMSS. */
static int utc_digits(const u8 *v, u64 *out) {
  u64 yy, rest;
  if (!digits(v, 2, &yy)) return 0;
  if (!digits(v + 2, 10, &rest)) return 0;
  *out = (yy + century(yy)) * 10000000000ULL + rest;
  return 1;
}

/* RFC 5280 4.1.2.5.1. UTCTime is YYMMDDHHMMSSZ. */
static int utctime(quic_span v, u64 *out) {
  if (!zterm(v, 13)) return 0;
  return utc_digits(v.p, out);
}

/* RFC 5280 4.1.2.5.2. GeneralizedTime is YYYYMMDDHHMMSSZ. */
static int gentime(quic_span v, u64 *out) {
  if (!zterm(v, 15)) return 0;
  return digits(v.p, 14, out);
}

/* Decode a Time (UTCTime or GeneralizedTime) into YYYYMMDDHHMMSS. */
static int time_value(u8 tag, quic_span v, u64 *out) {
  if (tag == DER_UTCTIME) return utctime(v, out);
  if (tag == DER_GENTIME) return gentime(v, out);
  return 0;
}

/* Position c before the validity element, inside the tbs SEQUENCE value. */
static int tbs_to_validity(quic_span tbs, quic_derseq *c) {
  return quic_x509_tbs_cursor(tbs, c) && quic_derseq_skip(c, VALIDITY_SKIP);
}

/* Read one Time element of c into *out. */
static int next_time(quic_derseq *c, u64 *out) {
  u8        tag;
  quic_span v;
  if (!quic_derseq_next(c, &tag, &v)) return 0;
  return time_value(tag, v, out);
}

/* RFC 5280 4.1.2.5. Extract notBefore and notAfter from the Validity value. */
static int validity_bounds(quic_span val, u64 *nb, u64 *na) {
  quic_derseq c;
  quic_derseq_init(&c, val);
  return next_time(&c, nb) && next_time(&c, na);
}

/* The Validity SEQUENCE value out of tbs. */
static int reach_validity(quic_span tbs, quic_span *v) {
  quic_derseq c;
  if (!tbs_to_validity(tbs, &c)) return 0;
  return quic_derseq_next_tagged(&c, QUIC_DER_SEQUENCE, v);
}

/* notBefore <= now <= notAfter. */
static int in_window(u64 nb, u64 na, u64 now) { return nb <= now && now <= na; }

int quic_x509_validity_ok(quic_span tbs, u64 now) {
  quic_span v;
  u64       nb, na;
  if (!reach_validity(tbs, &v)) return 0;
  return validity_bounds(v, &nb, &na) && in_window(nb, na, now);
}
