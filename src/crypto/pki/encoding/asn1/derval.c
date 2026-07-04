#include "crypto/pki/encoding/asn1/derval.h"

/* Byte-equal over n octets. */
static int der_bytes_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

int quic_der_oid_equal(quic_span oid, quic_span expected) {
  if (oid.n != expected.n) return 0;
  return der_bytes_eq(oid.p, expected.p, oid.n);
}

/* X.690 8.3.2. A leading 0x00 is a pad only when more octets follow. */
static int der_has_pad(quic_span val) { return val.n > 1 && val.p[0] == 0x00; }

/* Empty or negative (top bit of the first octet set, X.690 8.3.2 two's
 * complement) integers have no unsigned magnitude. */
static int der_int_bad(quic_span val) {
  return val.n == 0 || (val.p[0] & 0x80);
}

/* Point m at the unsigned magnitude. 1 if usable, else 0. */
static int der_int_mag(quic_span val, quic_span* m) {
  if (der_int_bad(val)) return 0;
  usz pad = der_has_pad(val) ? 1 : 0;
  *m      = quic_span_of(val.p + pad, val.n - pad);
  return 1;
}

/* Big-endian accumulate; nlen must be <= 8. */
static u64 der_be(const u8* p, usz nlen) {
  u64 v = 0;
  for (usz i = 0; i < nlen; i++) v = (v << 8) | p[i];
  return v;
}

int quic_der_uint(const u8* val, usz val_len, u64* out) {
  quic_span m;
  if (!der_int_mag(quic_span_of(val, val_len), &m)) return 0;
  if (m.n > 8) return 0;
  *out = der_be(m.p, m.n);
  return 1;
}
