#ifndef QUIC_CASTORE_CASTORE_H
#define QUIC_CASTORE_CASTORE_H

#include "sys/syscall.h"

/* RFC 5280 6.1. A trust anchor store: a fixed-size set of root CA
 * certificates (DER). Entries view the caller's buffers; nothing is copied. */

#define QUIC_CASTORE_MAX 8

typedef struct {
    const u8 *cert;
    usz len;
} quic_castore_entry;

typedef struct {
    quic_castore_entry roots[QUIC_CASTORE_MAX];
    usz count;
} quic_castore;

/* Empty the store. */
void quic_castore_init(quic_castore *s);

/* RFC 5280 6.1. Register one root CA certificate (DER, cert_der..+len).
 * Returns 1 on success, 0 if the store is full or the input is malformed. */
int quic_castore_add(quic_castore *s, const u8 *cert_der, usz len);

/* RFC 5280 6.1. Find a registered root whose subject Name equals issuer_dn
 * (a Name SEQUENCE view, header included). On a match views the root DER in
 * *root / *root_len and returns 1; returns 0 if none matches. */
int quic_castore_find_by_subject(const quic_castore *s,
                                 const u8 *issuer_dn, usz dn_len,
                                 const u8 **root, usz *root_len);

#endif
