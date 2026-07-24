#ifndef QUIC_QPACKDYN_ENC_STREAM_H
#define QUIC_QPACKDYN_ENC_STREAM_H

#include "app/qpack/qpack/dyntable.h"

/* RFC 9204 4.3 / 4.3.1 / 5. Apply the QPACK encoder-stream instructions this
 * SDK's server understands directly against the connection's dynamic table.
 * Only Set Dynamic Table Capacity (4.3.1) is interpreted here -- an encoder
 * instruction this SDK does not decode (Insert With Name Reference/Literal
 * Name, Duplicate, 4.3.2/4.3.3/4.3.4) has no string-decoding support on this
 * stream and is left unconsumed rather than misread. */

/* Try to decode and apply one Set Dynamic Table Capacity instruction (RFC
 * 9204 4.3.1) at the head of buf against t, honoring the server's own
 * advertised max_table_capacity (RFC 9204 5, 9204-032). Returns bytes
 * consumed on success, 0 if buf's leading byte is not a Set Dynamic Table
 * Capacity instruction, is truncated, or names a capacity exceeding
 * max_table_capacity (in which case *err is set to
 * QUIC_QPACK_ENCODER_STREAM_ERROR; *err is left unchanged on any other
 * return value). */
usz quic_qdyn_enc_apply_capacity(
    quic_span buf, quic_qpack_dyn* t, u64 max_table_capacity, u16* err);

#endif
