#ifndef QUIC_TPARAM_TPARAM_H
#define QUIC_TPARAM_TPARAM_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 18: transport parameters are a sequence of
 * (id: varint)(length: varint)(value: length bytes).
 * Integer-valued parameters carry a varint as their whole value. */

/* Parameter IDs (RFC 9000 18.2). */
#define QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID 0x00
#define QUIC_TP_MAX_IDLE_TIMEOUT        0x01
#define QUIC_TP_STATELESS_RESET_TOKEN   0x02
#define QUIC_TP_MAX_UDP_PAYLOAD_SIZE    0x03
#define QUIC_TP_INITIAL_MAX_DATA        0x04
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  0x05
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x06
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI         0x07
#define QUIC_TP_INITIAL_MAX_STREAMS_BIDI 0x08
#define QUIC_TP_INITIAL_MAX_STREAMS_UNI  0x09
#define QUIC_TP_ACK_DELAY_EXPONENT      0x0a
#define QUIC_TP_MAX_ACK_DELAY           0x0b
#define QUIC_TP_DISABLE_ACTIVE_MIGRATION 0x0c
#define QUIC_TP_PREFERRED_ADDRESS       0x0d
#define QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT 0x0e
#define QUIC_TP_INITIAL_SOURCE_CONNECTION_ID 0x0f
#define QUIC_TP_RETRY_SOURCE_CONNECTION_ID   0x10

/* Encode one integer-valued parameter (id, varint value) into buf of cap
 * bytes. Returns bytes written, or 0 if it does not fit / value out of range. */
usz quic_tparam_put_int(u8 *buf, usz cap, u64 id, u64 value);

/* Decode one parameter at buf (n readable). On success sets *id, *value
 * (decoded as a varint) and returns total bytes consumed; 0 on malformed
 * input or a value whose length is not a single varint. */
usz quic_tparam_get_int(const u8 *buf, usz n, u64 *id, u64 *value);

#endif
