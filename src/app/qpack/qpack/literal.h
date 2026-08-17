#ifndef QUIC_QPACK_LITERAL_H
#define QUIC_QPACK_LITERAL_H

#include "app/qpack/qpack/field.h"

/* RFC 9204 4.5.4. Literal Field Line With Name Reference: pattern 01NTiiii,
 * N=never-indexed, T=static, a 4-bit prefixed name index, then a value string
 * literal. RFC 9204 4.5.6. Literal Field Line With Literal Name: pattern
 * 001NHiii, N=never-indexed, H=name Huffman flag, a 3-bit prefixed name length
 * and that many name octets, then a value string literal. The encoder emits
 * raw (H=0) names; the decoder accepts H=0 (raw) and H=1 (Huffman) names. */

/** A name reference: the table index plus the T and N flag bits. */
typedef struct {
  u64 index;
  int is_static; /* T */
  int never;     /* N */
} quic_qpack_nameref;

/* Encode a name-reference field line: *r plus the value. Returns bytes
 * written, or 0 if it does not fit. */
usz quic_qpack_literal_namref_encode(
    wired_mspan buf, const quic_qpack_nameref* r, wired_span value);

/* Decode a name-reference field line into *r and the value (into val, length
 * to val->len). Returns bytes consumed, or 0 on a non-matching pattern,
 * truncation, or value overflow. */
usz quic_qpack_literal_namref_decode(
    wired_span buf, quic_qpack_nameref* r, wired_obuf* val);

/* Encode a literal-name field line: never flag plus the (name, value) pair.
 * Returns bytes written, or 0 if it does not fit. */
usz quic_qpack_literal_name_encode(
    wired_mspan buf, int never, const quic_qpack_field* f);

/* Decode a literal-name field line into *never and the (name, value) buffers.
 * A H=1 name is Huffman-decoded. Returns bytes consumed, or 0 on a
 * non-matching pattern, truncation, or overflow. */
usz quic_qpack_literal_name_decode(
    wired_span buf, int* never, quic_qpack_fieldbuf* out);

/* RFC 9204 4.5.5. Literal Field Line With Post-Base Name Reference: pattern
 * 0000Niii, N=never-indexed, a 3-bit prefixed post-Base index into the
 * dynamic table (an entry inserted after the section's Base), then a value
 * string literal. Always dynamic-table; there is no static-table form. */

/** A post-Base name reference: the post-Base index plus the N flag bit. */
typedef struct {
  u64 index;
  int never; /* N */
} quic_qpack_postbaseref;

/* Encode a post-Base name-reference field line: *r plus the value. Returns
 * bytes written, or 0 if it does not fit. */
usz quic_qpack_literal_postbase_encode(
    wired_mspan buf, const quic_qpack_postbaseref* r, wired_span value);

/* Decode a post-Base name-reference field line into *r and the value (into
 * val, length to val->len). Returns bytes consumed, or 0 on a non-matching
 * pattern, truncation, or value overflow. */
usz quic_qpack_literal_postbase_decode(
    wired_span buf, quic_qpack_postbaseref* r, wired_obuf* val);

#endif
