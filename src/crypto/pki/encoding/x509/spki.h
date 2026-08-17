#ifndef X509_SPKI_H
#define X509_SPKI_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2.7. subjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }.
 * Descends tbsCertificate and views the algorithm OID and the key bits.
 * Returns 1 ok, 0 on malformed input. */
int x509_public_key(wired_span tbs, wired_span* alg_oid, wired_span* key);

/* RFC 5280 4.1.2.7. 1 if the OID is id-ecPublicKey / rsaEncryption. */
int x509_is_ec(wired_span alg_oid);
int x509_is_rsa(wired_span alg_oid);

/* RFC 8410 3. 1 if the OID is id-X25519 (1.3.101.110) / id-X448
 * (1.3.101.111) / id-Ed25519 (1.3.101.112) / id-Ed448 (1.3.101.113). This
 * SDK implements Ed25519 signing/verification only; X25519, X448, and Ed448
 * are recognized (so callers can distinguish "unsupported known algorithm"
 * from "malformed/unknown OID") but have no key-agreement or signature
 * implementation behind them. */
int x509_is_x25519(wired_span alg_oid);
int x509_is_x448(wired_span alg_oid);
int x509_is_ed25519(wired_span alg_oid);
int x509_is_ed448(wired_span alg_oid);

/* SEC1 / RFC 5480. View the namedCurve OID (the AlgorithmIdentifier
 * parameters of an id-ecPublicKey SPKI). Returns 1 ok, 0 on malformed input
 * or a non-EC key. */
int x509_ec_curve(wired_span tbs, wired_span* curve_oid);

/* 1 if the namedCurve OID is prime256v1 / secp384r1. */
int x509_is_p256(wired_span oid);
int x509_is_p384(wired_span oid);

/* RFC 5480 2.1.2. 1 if the SubjectPublicKeyInfo algorithm OID is the
 * restricted id-ecDH (1.3.132.1.12) / id-ecMQV (1.3.132.1.13) key-agreement
 * identifier (as opposed to the unrestricted id-ecPublicKey). */
int x509_is_ecdh(wired_span alg_oid);
int x509_is_ecmqv(wired_span alg_oid);

/* RFC 5480 2.1.2. 1 if tbs's SubjectPublicKeyInfo algorithm is not
 * id-ecDH/id-ecMQV, or it is and a well-formed ECParameters namedCurve is
 * present (mandatory for those two algorithms). 0 if the algorithm is
 * id-ecDH/id-ecMQV but ECParameters is absent/malformed, or tbs is
 * malformed. */
int x509_ec_restricted_params_ok(wired_span tbs);

#endif
