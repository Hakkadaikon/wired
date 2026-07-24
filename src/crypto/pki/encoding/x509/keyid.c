#include "crypto/pki/encoding/x509/keyid.h"

#include "crypto/pki/encoding/x509/x509.h"

/* id-ce-authorityKeyIdentifier = 2.5.29.35 */
static const u8 oid_akid[] = {0x55, 0x1d, 0x23};
/* id-ce-subjectKeyIdentifier = 2.5.29.14 */
static const u8 oid_skid[] = {0x55, 0x1d, 0x0e};

int quic_x509_authority_key_id(quic_span tbs, quic_span* val) {
  return quic_x509_find_ext(tbs, quic_span_of(oid_akid, sizeof(oid_akid)), val);
}

int quic_x509_subject_key_id(quic_span tbs, quic_span* val) {
  return quic_x509_find_ext(tbs, quic_span_of(oid_skid, sizeof(oid_skid)), val);
}
