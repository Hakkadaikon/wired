#ifndef QUIC_CASTORE_CASTORE_H
#define QUIC_CASTORE_CASTORE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 6.1. A trust anchor store over a caller-supplied entry array (a
 * real trust store holds ~150 roots; the caller sizes it). Entries view the
 * caller's DER buffers; nothing is copied — the array and every registered
 * DER must outlive the store. */

typedef quic_span quic_castore_entry; /* one root certificate DER view */

typedef struct {
  quic_castore_entry* roots; /* caller-owned array of cap entries */
  usz                 cap;
  usz                 count;
} quic_castore;

/* Bind the store to the caller's entry array and empty it. */
void quic_castore_init(quic_castore* s, quic_castore_entry* roots, usz cap);

/* RFC 5280 6.1. Register one root CA certificate (DER).
 * Returns 1 on success, 0 if the store is full or the input is malformed. */
int quic_castore_add(quic_castore* s, quic_span cert_der);

/* RFC 5280 6.1. Find a registered root whose subject Name equals issuer_dn
 * (a Name SEQUENCE view, header included). On a match views the root DER in
 * *root and returns 1; returns 0 if none matches. */
int quic_castore_find_by_subject(
    const quic_castore* s, quic_span issuer_dn, quic_span* root);

#endif
