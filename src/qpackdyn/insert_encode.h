#ifndef QUIC_QPACKDYN_INSERT_ENCODE_H
#define QUIC_QPACKDYN_INSERT_ENCODE_H

#include "sys/syscall.h"

/* RFC 9204 4.3.3. Insert With Literal Name (encoder stream): first byte
 * 01Hxxxxx with a 5-bit prefixed name length (H=0, raw), then the name octets,
 * then the value as a 7-bit prefixed (H=0) string literal. Produces the
 * encoder-stream instruction that adds (name, value) to the dynamic table. */
usz quic_qdyn_insert_literal(const u8 *name, usz name_len, const u8 *value,
                             usz value_len, u8 *out, usz cap, usz *out_len);

#endif
