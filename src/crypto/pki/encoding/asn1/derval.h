#ifndef QUIC_ASN1_DERVAL_H
#define QUIC_ASN1_DERVAL_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* X.690 8.3 / 8.19. Value extraction for INTEGER and OBJECT IDENTIFIER. */

/* Compare an OID value blob (post tag+length) against expected bytes.
 * Returns 1 if equal, 0 otherwise. */
int quic_der_oid_equal(quic_span oid, quic_span expected);

/* Decode a DER INTEGER value blob into *out. Strips a single leading 0x00
 * pad. Returns 1 ok; 0 if negative, empty, or wider than 8 octets. */
int quic_der_uint(const u8 *val, usz val_len, u64 *out);

#endif
