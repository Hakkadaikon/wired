#include "crypto/pki/encoding/x509/eku.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/x509.h"

/* id-ce-extKeyUsage = 2.5.29.37 */
static const u8 oid_eku[] = {0x55, 0x1d, 0x25};

const u8 quic_x509_oid_server_auth[8] = {0x2b, 0x06, 0x01, 0x05,
                                         0x05, 0x07, 0x03, 0x01};

/* One KeyPurposeId element equals purpose_oid. */
static int eku_id_matches(u8 tag, quic_span id, quic_span purpose_oid) {
  return tag == QUIC_DER_OID && quic_der_oid_equal(id, purpose_oid);
}

/* RFC 5280 4.2.1.12. Scan the SEQUENCE OF KeyPurposeId for purpose_oid. */
static int eku_list_has(quic_span list, quic_span purpose_oid) {
  quic_derseq c;
  u8          tag;
  quic_span   id;
  quic_derseq_init(&c, list);
  while (quic_derseq_next(&c, &tag, &id))
    if (eku_id_matches(tag, id, purpose_oid)) return 1;
  return 0;
}

/* The extKeyUsage extnValue: a SEQUENCE OF KeyPurposeId. */
static int eku_locate(quic_span tbs, quic_span* list) {
  quic_span val;
  if (!quic_x509_find_ext(tbs, quic_span_of(oid_eku, sizeof(oid_eku)), &val))
    return 0;
  return quic_der_seq(val, list);
}

int quic_x509_eku_allows(quic_span tbs, quic_span purpose_oid) {
  quic_span list;
  if (!eku_locate(tbs, &list)) return 1;
  return eku_list_has(list, purpose_oid);
}
