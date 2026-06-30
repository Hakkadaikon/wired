#include "crypto/pki/cert/tbscert/sigalg.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"

int quic_tbscert_sigalg_oid(const quic_tbscert *t, const u8 **oid, usz *len) {
  quic_derseq c;
  u8          tag;
  quic_derseq_init(&c, t->sig_alg, t->sig_alg_len);
  if (!quic_derseq_next(&c, &tag, oid, len)) return 0;
  return tag == QUIC_DER_OID;
}

int quic_tbscert_sigalg_matches(
    const quic_tbscert *t, const u8 *outer_oid, usz outer_len) {
  const u8 *oid;
  usz       len;
  if (!quic_tbscert_sigalg_oid(t, &oid, &len)) return 0;
  return quic_der_oid_equal(oid, len, outer_oid, outer_len);
}
