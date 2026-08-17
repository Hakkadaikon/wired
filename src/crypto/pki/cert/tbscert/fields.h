#ifndef QUIC_TBSCERT_FIELDS_H
#define QUIC_TBSCERT_FIELDS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** RFC 5280 4.1.2. TBSCertificate ::= SEQUENCE {
 *   version [0] EXPLICIT INTEGER DEFAULT v1, serialNumber INTEGER,
 *   signature AlgorithmIdentifier, issuer Name, validity Validity,
 *   subject Name, subjectPublicKeyInfo, ... extensions [3] EXPLICIT }.
 * Each field views the element VALUE (tag+length stripped) inside the
 * caller's buffer; nothing is copied. A zero-length field is absent. */
typedef struct {
  wired_span version;    /* [0] EXPLICIT inner INTEGER value (absent => v1) */
  wired_span serial;     /* serialNumber INTEGER value */
  wired_span sig_alg;    /* signature AlgorithmIdentifier SEQUENCE value */
  wired_span issuer;     /* issuer Name SEQUENCE value */
  wired_span validity;   /* validity SEQUENCE value */
  wired_span subject;    /* subject Name SEQUENCE value */
  wired_span spki;       /* subjectPublicKeyInfo SEQUENCE value */
  wired_span extensions; /* [3] EXPLICIT inner SEQUENCE value (may be absent) */
} quic_tbscert;

/* RFC 5280 4.1.2. Parse a tbsCertificate (header included) into out.
 * Returns 1 ok, 0 on malformed input. */
int quic_tbscert_parse(wired_span tbs, quic_tbscert* out);

#endif
