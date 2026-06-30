#ifndef QUIC_ECDSASIG_DER_INT_H
#define QUIC_ECDSASIG_DER_INT_H

#include "common/platform/sys/syscall.h"

/* SEC1 C.5 / RFC 5280. DER-encode one 32-octet big-endian unsigned value as an
 * ASN.1 INTEGER: strip leading 0x00 to the minimal form (a single 0x00 when the
 * value is zero), then prepend 0x00 when the leading octet's top bit is set so
 * the integer stays positive. Emits 0x02 <len> <bytes> into out (cap octets)
 * and sets *out_len. Returns 1 ok, 0 if it would not fit. */
int quic_ecdsasig_encode_integer(
    const u8 val[32], u8 *out, usz cap, usz *out_len);

#endif
