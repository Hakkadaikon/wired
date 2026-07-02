#include "crypto/pki/cert/tbscert/sigalg.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"

int quic_tbscert_sigalg_oid(const quic_tbscert *t, quic_span *oid) {
  quic_derseq c;
  quic_derseq_init(&c, t->sig_alg);
  return quic_derseq_next_tagged(&c, QUIC_DER_OID, oid);
}

int quic_tbscert_sigalg_matches(const quic_tbscert *t, quic_span outer_oid) {
  quic_span oid;
  if (!quic_tbscert_sigalg_oid(t, &oid)) return 0;
  return quic_der_oid_equal(oid, outer_oid);
}
