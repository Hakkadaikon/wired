#include "crypto/pki/cert/tbscert/sigalg.h"

#include "common/bytes/util/bytes.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"

/* RFC 5280 4.1.1.2 AlgorithmIdentifier: view the OID value and the
 * parameter octets after it (empty when absent). */
static int sigalg_split(const tbscert* t, wired_span* oid, wired_span* params) {
  derseq c;
  derseq_init(&c, t->sig_alg);
  if (!derseq_next_tagged(&c, DER_OID, oid)) {
    return 0;
  }
  *params = wired_span_of(c.p + c.off, c.len - c.off);
  return 1;
}

int tbscert_sigalg_oid(const tbscert* t, wired_span* oid) {
  wired_span params;
  return sigalg_split(t, oid, &params);
}

int tbscert_sigalg_matches(
    const tbscert* t, wired_span outer_oid, wired_span outer_params) {
  wired_span oid, params;
  if (!sigalg_split(t, &oid, &params)) {
    return 0;
  }
  return bytes_span_eq(oid, outer_oid) && bytes_span_eq(params, outer_params);
}
