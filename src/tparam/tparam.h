#ifndef QUIC_TPARAM_TPARAM_H
#define QUIC_TPARAM_TPARAM_H

#include "sys/syscall.h"

/* RFC 9000 18: transport parameters are a sequence of
 * (id: varint)(length: varint)(value: length bytes).
 * Integer-valued parameters carry a varint as their whole value. */

/* A few common parameter IDs (RFC 9000 18.2). */
#define QUIC_TP_MAX_IDLE_TIMEOUT        0x01
#define QUIC_TP_MAX_UDP_PAYLOAD_SIZE    0x03
#define QUIC_TP_INITIAL_MAX_DATA        0x04
#define QUIC_TP_INITIAL_MAX_STREAMS_BIDI 0x08
#define QUIC_TP_INITIAL_MAX_STREAMS_UNI  0x09

/* Encode one integer-valued parameter (id, varint value) into buf of cap
 * bytes. Returns bytes written, or 0 if it does not fit / value out of range. */
usz quic_tparam_put_int(u8 *buf, usz cap, u64 id, u64 value);

/* Decode one parameter at buf (n readable). On success sets *id, *value
 * (decoded as a varint) and returns total bytes consumed; 0 on malformed
 * input or a value whose length is not a single varint. */
usz quic_tparam_get_int(const u8 *buf, usz n, u64 *id, u64 *value);

#endif
