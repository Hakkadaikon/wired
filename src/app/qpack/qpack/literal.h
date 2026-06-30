#ifndef QUIC_QPACK_LITERAL_H
#define QUIC_QPACK_LITERAL_H

#include "common/platform/sys/syscall.h"

/* RFC 9204 4.5.4. Literal Field Line With Name Reference: pattern 01NTiiii,
 * N=never-indexed, T=static, a 4-bit prefixed name index, then a value string
 * literal. RFC 9204 4.5.6. Literal Field Line With Literal Name: pattern
 * 001NHiii, N=never-indexed, H=name Huffman flag, a 3-bit prefixed name length
 * and that many name octets, then a value string literal. The encoder emits
 * raw (H=0) names; the decoder accepts H=0 (raw) and H=1 (Huffman) names. */

/* Encode a name-reference field line: name index/is_static/never plus the
 * value (vlen octets). Returns bytes written, or 0 if it does not fit. */
usz quic_qpack_literal_namref_encode(
    u8       *buf,
    usz       cap,
    u64       index,
    int       is_static,
    int       never,
    const u8 *value,
    usz       vlen);

/* Decode a name-reference field line into *index, *is_static, *never and the
 * value (into val of vcap octets, length to *vlen). Returns bytes consumed,
 * or 0 on a non-matching pattern, truncation, or value overflow. */
usz quic_qpack_literal_namref_decode(
    const u8 *buf,
    usz       n,
    u64      *index,
    int      *is_static,
    int      *never,
    u8       *val,
    usz       vcap,
    usz      *vlen);

/* Encode a literal-name field line: never flag, name (nlen octets), value
 * (vlen octets). Returns bytes written, or 0 if it does not fit. */
usz quic_qpack_literal_name_encode(
    u8       *buf,
    usz       cap,
    int       never,
    const u8 *name,
    usz       nlen,
    const u8 *value,
    usz       vlen);

/* Decode a literal-name field line into *never, the name (into nm of ncap,
 * length to *nlen) and the value (into val of vcap, length to *vlen). A H=1
 * name is Huffman-decoded. Returns bytes consumed, or 0 on a non-matching
 * pattern, truncation, or overflow. */
usz quic_qpack_literal_name_decode(
    const u8 *buf,
    usz       n,
    int      *never,
    u8       *nm,
    usz       ncap,
    usz      *nlen,
    u8       *val,
    usz       vcap,
    usz      *vlen);

#endif
