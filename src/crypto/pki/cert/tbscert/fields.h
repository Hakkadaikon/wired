#ifndef QUIC_TBSCERT_FIELDS_H
#define QUIC_TBSCERT_FIELDS_H

#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2. TBSCertificate ::= SEQUENCE {
 *   version [0] EXPLICIT INTEGER DEFAULT v1, serialNumber INTEGER,
 *   signature AlgorithmIdentifier, issuer Name, validity Validity,
 *   subject Name, subjectPublicKeyInfo, ... extensions [3] EXPLICIT }.
 * Each field is a view (ptr+len) of the element VALUE (tag+length stripped)
 * into the caller's buffer; nothing is copied. A zero-length field is absent.
 */
typedef struct {
  const u8 *version; /* [0] EXPLICIT inner INTEGER value (absent => v1) */
  usz       version_len;
  const u8 *serial; /* serialNumber INTEGER value */
  usz       serial_len;
  const u8 *sig_alg; /* signature AlgorithmIdentifier SEQUENCE value */
  usz       sig_alg_len;
  const u8 *issuer; /* issuer Name SEQUENCE value */
  usz       issuer_len;
  const u8 *validity; /* validity SEQUENCE value */
  usz       validity_len;
  const u8 *subject; /* subject Name SEQUENCE value */
  usz       subject_len;
  const u8 *spki; /* subjectPublicKeyInfo SEQUENCE value */
  usz       spki_len;
  const u8 *extensions; /* [3] EXPLICIT inner SEQUENCE value (may be absent) */
  usz       extensions_len;
} quic_tbscert;

/* RFC 5280 4.1.2. Parse a tbsCertificate (header included) into out.
 * Returns 1 ok, 0 on malformed input. */
int quic_tbscert_parse(const u8 *tbs, usz tbs_len, quic_tbscert *out);

#endif
