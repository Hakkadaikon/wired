#ifndef QUIC_X509_X509_H
#define QUIC_X509_X509_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "crypto/pki/encoding/asn1/derseq.h"

/* RFC 5280 4.1. Certificate ::= SEQUENCE {
 *   tbsCertificate, signatureAlgorithm, signatureValue }.
 * Views point into the caller's buffer; nothing is copied. */
typedef struct {
  quic_span tbs;         /* tbsCertificate, header included (signed bytes) */
  quic_span sig_alg_oid; /* OID value inside signatureAlgorithm */
  quic_span sig;         /* signatureValue BIT STRING value */
} quic_x509;

/* Parse the top-level certificate. Returns 1 ok, 0 on malformed input. */
int quic_x509_parse(quic_span cert, quic_x509* out);

/* RFC 5280 4.1. Open a cursor inside the tbs SEQUENCE value, past the
 * optional [0] version, before serialNumber. Returns 1 ok, 0 on malformed
 * input. */
int quic_x509_tbs_cursor(quic_span tbs, quic_derseq* c);

/* RFC 5280 4.1.2.9. Find the extnValue OCTET STRING of the extension whose
 * extnID equals oid, inside the tbs [3] extensions. Returns 1 and views the
 * value, 0 if absent or malformed. */
int quic_x509_find_ext(quic_span tbs, quic_span oid, quic_span* val);

/* RFC 5280 4.2. 1 if any extension in tbs is marked critical (TRUE) and its
 * extnID is not one this SDK understands (basicConstraints, subjectAltName,
 * keyUsage, extKeyUsage); 0 if every critical extension is known, or there
 * are no extensions at all. RFC 5280 4.2 CAs/applications MUST reject a
 * certificate carrying an unrecognized critical extension. */
int quic_x509_has_unknown_critical(quic_span tbs);

#endif
