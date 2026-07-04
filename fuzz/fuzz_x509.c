/* libFuzzer harness for the X.509 certificate parser (RFC 5280 4.1) and the
 * TBSCertificate field extractor (RFC 5280 4.1.2). Hosted build only —
 * mirrors tests/run.c's unity-include style, but this file itself may use
 * the standard library since it lives outside src/.
 *
 * A certificate parser's job is to safely reject arbitrary bytes, so no
 * structured seed is needed: raw DER bytes drive both quic_x509_parse and,
 * on success, the tbsCertificate sub-parsers and extension lookup. */
#include <stddef.h>
#include <stdint.h>

#include "crypto/pki/encoding/asn1/der.c"
#include "crypto/pki/encoding/asn1/derseq.c"
#include "crypto/pki/encoding/asn1/derval.c"
#include "crypto/pki/encoding/x509/x509.c"
#include "crypto/pki/cert/tbscert/fields.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  quic_span cert = quic_span_of((const u8 *)data, (usz)size);

  quic_x509 x;
  if (!quic_x509_parse(cert, &x)) return 0;

  /* tbsCertificate is well-formed enough to have been sliced out above;
   * fuzz its own structured sub-parsers on the same bytes. */
  quic_tbscert tbs;
  quic_tbscert_parse(x.tbs, &tbs);

  quic_derseq c;
  quic_x509_tbs_cursor(x.tbs, &c);

  /* RFC 5280 4.2.1.9 basicConstraints OID, walked regardless of whether it
   * is actually present — exercises the extensions-scan path too. */
  static const u8 basic_constraints_oid[] = {0x55, 0x1d, 0x13};
  quic_span       val;
  quic_x509_find_ext(x.tbs, quic_span_of(basic_constraints_oid, 3), &val);

  return 0;
}
