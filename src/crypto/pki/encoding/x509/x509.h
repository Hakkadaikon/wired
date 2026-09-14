#ifndef X509_X509_H
#define X509_X509_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "crypto/pki/encoding/asn1/derseq.h"

/** RFC 5280 4.1. Certificate ::= SEQUENCE {
 *   tbsCertificate, signatureAlgorithm, signatureValue }.
 * Views point into the caller's buffer; nothing is copied. */
typedef struct {
  wired_span tbs;         /* tbsCertificate, header included (signed bytes) */
  wired_span sig_alg_oid; /* OID value inside signatureAlgorithm */
  wired_span sig;         /* signatureValue BIT STRING value */
} x509;

/* Parse the top-level certificate. Returns 1 ok, 0 on malformed input. */
int x509_parse(wired_span cert, x509* out);

/* RFC 5280 4.1. Open a cursor inside the tbs SEQUENCE value, past the
 * optional [0] version, before serialNumber. Returns 1 ok, 0 on malformed
 * input. */
int x509_tbs_cursor(wired_span tbs, derseq* c);

/* RFC 5280 4.1.2.9. Find the extnValue OCTET STRING of the extension whose
 * extnID equals oid, inside the tbs [3] extensions. Returns 1 and views the
 * value, 0 if absent or malformed. */
int x509_find_ext(wired_span tbs, wired_span oid, wired_span* val);

/* RFC 5280 4.2. 1 if any extension in tbs is marked critical (TRUE) and its
 * extnID is not one this SDK understands (basicConstraints, subjectAltName,
 * keyUsage, extKeyUsage); 0 if every critical extension is known, or there
 * are no extensions at all. RFC 5280 4.2 CAs/applications MUST reject a
 * certificate carrying an unrecognized critical extension. */
int x509_has_unknown_critical(wired_span tbs);

/* RFC 5280 4.2: "A certificate MUST NOT include more than one instance of a
 * particular extension." 1 if some extnID appears in tbs's extensions more
 * than once (x509_find_ext consults only the first instance, so a repeated
 * extension would otherwise be silently ignored -- a certificate with a
 * duplicate must be rejected instead); 0 if every extnID is unique or there
 * are no extensions at all. */
int x509_has_duplicate_ext(wired_span tbs);

#endif
