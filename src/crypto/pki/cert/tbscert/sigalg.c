#include "crypto/pki/cert/tbscert/sigalg.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"

int tbscert_sigalg_oid(const tbscert* t, wired_span* oid) {
  derseq c;
  derseq_init(&c, t->sig_alg);
  return derseq_next_tagged(&c, QUIC_DER_OID, oid);
}

int tbscert_sigalg_matches(const tbscert* t, wired_span outer_oid) {
  wired_span oid;
  if (!tbscert_sigalg_oid(t, &oid)) return 0;
  return der_oid_equal(oid, outer_oid);
}
