#ifndef QUIC_SELFCERT_DERENC_H
#define QUIC_SELFCERT_DERENC_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* X.690 8.1. Emit one DER TLV: tag + length (short / 0x81 / 0x82) + value.
 * Appends nothing on failure; on success sets out->len to the whole TLV
 * length. Returns 1 ok, 0 if it would not fit or len exceeds the long-form
 * ceiling. */
int quic_selfcert_der_tlv(u8 tag, quic_span val, quic_obuf* out);

#endif
