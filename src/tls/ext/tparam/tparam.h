#ifndef TPARAM_TPARAM_H
#define TPARAM_TPARAM_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 18: transport parameters are a sequence of
 * (id: varint)(length: varint)(value: length bytes).
 * Integer-valued parameters carry a varint as their whole value. */

/* Parameter IDs (RFC 9000 18.2). */
#define TP_ORIGINAL_DESTINATION_CONNECTION_ID 0x00
#define TP_MAX_IDLE_TIMEOUT 0x01
#define TP_STATELESS_RESET_TOKEN 0x02
#define TP_MAX_UDP_PAYLOAD_SIZE 0x03
#define TP_INITIAL_MAX_DATA 0x04
#define TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL 0x05
#define TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x06
#define TP_INITIAL_MAX_STREAM_DATA_UNI 0x07
#define TP_INITIAL_MAX_STREAMS_BIDI 0x08
#define TP_INITIAL_MAX_STREAMS_UNI 0x09
#define TP_ACK_DELAY_EXPONENT 0x0a
#define TP_MAX_ACK_DELAY 0x0b
#define TP_DISABLE_ACTIVE_MIGRATION 0x0c
#define TP_PREFERRED_ADDRESS 0x0d
#define TP_ACTIVE_CONNECTION_ID_LIMIT 0x0e
#define TP_INITIAL_SOURCE_CONNECTION_ID 0x0f
#define TP_RETRY_SOURCE_CONNECTION_ID 0x10
/* reset_stream_at (draft-ietf-quic-reliable-stream-reset 4): announces
 * support for the RESET_STREAM_AT frame (0x24). Empty-valued -- presence
 * alone is the signal, so it is encoded via the generic blob form
 * (tparam_put_blob/tparam_get_blob) with a zero-length value,
 * never tparam_put_int/get_int. */
#define TP_RESET_STREAM_AT 0x1d
/* max_datagram_frame_size (RFC 9221 3): the max DATAGRAM frame size this
 * endpoint will accept; 0 or absent means DATAGRAM frames are not supported,
 * RECOMMENDED value when supported is 65535. Encode/decode is just the
 * generic single-varint form below (tparam_put_int/get_int); any size
 * enforcement is a different domain's job. Defined in
 * app/datagram/datagram/datagram.h (TP_MAX_DATAGRAM_FRAME_SIZE) since
 * that domain owns the DATAGRAM frame codec this parameter gates -- not
 * redefined here to avoid a duplicate macro. */

/* Encode one integer-valued parameter (id, varint value) into out->p (out->cap
 * bytes). Returns bytes written, or 0 if it does not fit / value out of range.
 */
usz tparam_put_int(wired_obuf* out, u64 id, u64 value);

/* Decode one parameter at buf.p (buf.n readable). On success sets *id, *value
 * (decoded as a varint) and returns total bytes consumed; 0 on malformed
 * input or a value whose length is not a single varint. */
usz tparam_get_int(wired_span buf, u64* id, u64* value);

/* RFC 9000 7.4: scan a full transport-parameter TLV sequence and report
 * whether every parameter id is distinct. Returns 1 if all ids are unique,
 * 0 if any id repeats or the sequence is malformed
 * (TRANSPORT_PARAMETER_ERROR either way). */
int tparam_no_duplicates(wired_span buf);

#endif
