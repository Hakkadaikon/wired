#ifndef QUIC_X509_X509_H
#define QUIC_X509_X509_H

#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1. Certificate ::= SEQUENCE {
 *   tbsCertificate, signatureAlgorithm, signatureValue }.
 * Views point into the caller's buffer; nothing is copied. */
typedef struct {
  const u8 *tbs; /* tbsCertificate, header included (signed bytes) */
  usz       tbs_len;
  const u8 *sig_alg_oid; /* OID value inside signatureAlgorithm */
  usz       sig_alg_len;
  const u8 *sig; /* signatureValue BIT STRING value */
  usz       sig_len;
} quic_x509;

/* Parse the top-level certificate. Returns 1 ok, 0 on malformed input. */
int quic_x509_parse(const u8 *cert, usz len, quic_x509 *out);

#endif
