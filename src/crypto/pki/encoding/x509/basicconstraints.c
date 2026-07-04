#include "crypto/pki/encoding/x509/basicconstraints.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/x509/x509.h"

/* X.690 8.2. BOOLEAN universal tag. */
#define QUIC_DER_BOOLEAN 0x01

/* id-ce-basicConstraints = 2.5.29.19 */
static const u8 oid_bc[] = {0x55, 0x1d, 0x13};

/* X.690 11.1. A DER BOOLEAN encoding TRUE (single non-zero octet). */
static int bc_is_true_boolean(u8 tag, quic_span b) {
  return tag == QUIC_DER_BOOLEAN && b.n == 1 && b.p[0] != 0x00;
}

/* RFC 5280 4.2.1.9. cA is the optional leading BOOLEAN of the SEQUENCE. */
static int bc_ca_true(quic_span val) {
  quic_derseq c;
  u8          tag;
  quic_span   bc, b;
  if (!quic_der_seq(val, &bc)) return 0;
  quic_derseq_init(&c, bc);
  if (!quic_derseq_next(&c, &tag, &b)) return 0;
  return bc_is_true_boolean(tag, b);
}

/* The basicConstraints extnValue, if the extension is present. */
static int bc_locate(quic_span tbs, quic_span* val) {
  return quic_x509_find_ext(tbs, quic_span_of(oid_bc, sizeof(oid_bc)), val);
}

int quic_x509_is_ca(quic_span tbs) {
  quic_span val;
  if (!bc_locate(tbs, &val)) return 0;
  return bc_ca_true(val);
}

/* RFC 5280 4.2.1.9. The element after cA inside BasicConstraints, i.e. the
 * pathLenConstraint if present. Assumes cA is encoded (a CA cert must). */
static int bc_pathlen_elem(quic_span val, u8* tag, quic_span* b) {
  quic_derseq c;
  u8          t;
  quic_span   bc, x;
  if (!quic_der_seq(val, &bc)) return 0;
  quic_derseq_init(&c, bc);
  if (!quic_derseq_next(&c, &t, &x)) return 0;
  return quic_derseq_next(&c, tag, b);
}

/* X.690 8.3. Content octets form a well-formed non-negative INTEGER that
 * fits usz. */
static int bc_uint_wf(quic_span b) {
  return b.n >= 1 && b.n <= sizeof(usz) && !(b.p[0] & 0x80);
}

/* Big-endian content octets as a usz. */
static usz bc_uint(quic_span b) {
  usz v = 0;
  for (usz i = 0; i < b.n; i++) v = (v << 8) | b.p[i];
  return v;
}

/* pathLenConstraint INTEGER admits `depth`; a non-INTEGER trailing element or
 * a malformed/negative value rejects (fail closed). */
static int bc_pathlen_ok(u8 tag, quic_span b, usz depth) {
  if (tag != QUIC_DER_INTEGER || !bc_uint_wf(b)) return 0;
  return bc_uint(b) >= depth;
}

int quic_x509_pathlen_allows(quic_span tbs, usz depth) {
  quic_span val, b;
  u8        tag;
  if (!bc_locate(tbs, &val)) return 1;
  if (!bc_pathlen_elem(val, &tag, &b)) return 1;
  return bc_pathlen_ok(tag, b, depth);
}
