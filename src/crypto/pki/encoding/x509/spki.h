#ifndef QUIC_X509_SPKI_H
#define QUIC_X509_SPKI_H

#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2.7. subjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }.
 * Descends tbsCertificate and views the algorithm OID and the key bits.
 * Returns 1 ok, 0 on malformed input. */
int quic_x509_public_key(
    const u8  *tbs,
    usz        tbs_len,
    const u8 **alg_oid,
    usz       *alg_len,
    const u8 **key,
    usz       *key_len);

/* RFC 5280 4.1.2.7. 1 if the OID is id-ecPublicKey / rsaEncryption. */
int quic_x509_is_ec(const u8 *alg_oid, usz alg_len);
int quic_x509_is_rsa(const u8 *alg_oid, usz alg_len);

/* SEC1 / RFC 5480. View the namedCurve OID (the AlgorithmIdentifier
 * parameters of an id-ecPublicKey SPKI). Returns 1 ok, 0 on malformed input
 * or a non-EC key. */
int quic_x509_ec_curve(
    const u8 *tbs, usz tbs_len, const u8 **curve_oid, usz *curve_len);

/* 1 if the namedCurve OID is prime256v1 / secp384r1. */
int quic_x509_is_p256(const u8 *oid, usz oid_len);
int quic_x509_is_p384(const u8 *oid, usz oid_len);

#endif
