#ifndef QUIC_X509_SPKI_H
#define QUIC_X509_SPKI_H

#include "sys/syscall.h"

/* RFC 5280 4.1.2.7. subjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }.
 * Descends tbsCertificate and views the algorithm OID and the key bits.
 * Returns 1 ok, 0 on malformed input. */
int quic_x509_public_key(const u8 *tbs, usz tbs_len,
                         const u8 **alg_oid, usz *alg_len,
                         const u8 **key, usz *key_len);

/* RFC 5280 4.1.2.7. 1 if the OID is id-ecPublicKey / rsaEncryption. */
int quic_x509_is_ec(const u8 *alg_oid, usz alg_len);
int quic_x509_is_rsa(const u8 *alg_oid, usz alg_len);

#endif
