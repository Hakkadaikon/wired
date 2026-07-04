#ifndef QUIC_QPACKDYN_INSERT_ENCODE_H
#define QUIC_QPACKDYN_INSERT_ENCODE_H

#include "app/qpack/qpack/field.h"

/* RFC 9204 4.3.3. Insert With Literal Name (encoder stream): first byte
 * 01Hxxxxx with a 5-bit prefixed name length (H=0, raw), then the name octets,
 * then the value as a 7-bit prefixed (H=0) string literal. Produces the
 * encoder-stream instruction that adds f to the dynamic table. Returns bytes
 * written (also stored in out->len), or 0 if it does not fit. */
usz quic_qdyn_insert_literal(const quic_qpack_field* f, quic_obuf* out);

#endif
