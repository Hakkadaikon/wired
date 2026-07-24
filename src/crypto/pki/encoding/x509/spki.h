#ifndef QUIC_X509_SPKI_H
#define QUIC_X509_SPKI_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2.7. subjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }.
 * Descends tbsCertificate and views the algorithm OID and the key bits.
 * Returns 1 ok, 0 on malformed input. */
int quic_x509_public_key(quic_span tbs, quic_span* alg_oid, quic_span* key);

/* RFC 5280 4.1.2.7. 1 if the OID is id-ecPublicKey / rsaEncryption. */
int quic_x509_is_ec(quic_span alg_oid);
int quic_x509_is_rsa(quic_span alg_oid);

/* RFC 8410 3. 1 if the OID is id-X25519 (1.3.101.110) / id-X448
 * (1.3.101.111) / id-Ed25519 (1.3.101.112) / id-Ed448 (1.3.101.113). This
 * SDK implements Ed25519 signing/verification only; X25519, X448, and Ed448
 * are recognized (so callers can distinguish "unsupported known algorithm"
 * from "malformed/unknown OID") but have no key-agreement or signature
 * implementation behind them. */
int quic_x509_is_x25519(quic_span alg_oid);
int quic_x509_is_x448(quic_span alg_oid);
int quic_x509_is_ed25519(quic_span alg_oid);
int quic_x509_is_ed448(quic_span alg_oid);

/* SEC1 / RFC 5480. View the namedCurve OID (the AlgorithmIdentifier
 * parameters of an id-ecPublicKey SPKI). Returns 1 ok, 0 on malformed input
 * or a non-EC key. */
int quic_x509_ec_curve(quic_span tbs, quic_span* curve_oid);

/* 1 if the namedCurve OID is prime256v1 / secp384r1. */
int quic_x509_is_p256(quic_span oid);
int quic_x509_is_p384(quic_span oid);

#endif
