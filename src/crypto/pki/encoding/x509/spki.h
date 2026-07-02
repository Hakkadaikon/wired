#ifndef QUIC_X509_SPKI_H
#define QUIC_X509_SPKI_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2.7. subjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }.
 * Descends tbsCertificate and views the algorithm OID and the key bits.
 * Returns 1 ok, 0 on malformed input. */
int quic_x509_public_key(quic_span tbs, quic_span *alg_oid, quic_span *key);

/* RFC 5280 4.1.2.7. 1 if the OID is id-ecPublicKey / rsaEncryption. */
int quic_x509_is_ec(quic_span alg_oid);
int quic_x509_is_rsa(quic_span alg_oid);

/* SEC1 / RFC 5480. View the namedCurve OID (the AlgorithmIdentifier
 * parameters of an id-ecPublicKey SPKI). Returns 1 ok, 0 on malformed input
 * or a non-EC key. */
int quic_x509_ec_curve(quic_span tbs, quic_span *curve_oid);

/* 1 if the namedCurve OID is prime256v1 / secp384r1. */
int quic_x509_is_p256(quic_span oid);
int quic_x509_is_p384(quic_span oid);

#endif
