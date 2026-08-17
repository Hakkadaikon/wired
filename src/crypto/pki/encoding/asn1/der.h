#ifndef ASN1_DER_H
#define ASN1_DER_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* X.690 8.1. DER TLV: tag (1 octet) + length + value.
 * Length short form (<128) and long form 0x81/0x82 (1/2 octet length). */

/* X.690 8. Universal class tags used by X.509 (RFC 5280). */
#define DER_INTEGER 0x02
#define DER_BIT_STRING 0x03
#define DER_OCTET_STRING 0x04
#define DER_NULL 0x05
#define DER_OID 0x06
#define DER_SEQUENCE 0x30
#define DER_SET 0x31

/** One decoded TLV: its tag, a view of its value, and the octets it consumed
 * (header + value) from the input. */
typedef struct {
  u8         tag;
  wired_span val;
  usz        used;
} der_tlv;

/* Read one TLV from buf. The value views into buf; nothing is copied.
 * Returns 1 ok, 0 on error. */
int der_read(wired_span buf, der_tlv* out);

/* Read one TLV from buf, requiring a SEQUENCE tag; views its value.
 * Returns 1 ok, 0 on error or a different tag. */
int der_seq(wired_span buf, wired_span* val);

#endif
