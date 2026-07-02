#ifndef QUIC_QPACK_STRING_H
#define QUIC_QPACK_STRING_H

#include "common/bytes/span/span.h"

/* RFC 9204 4.1.2 / RFC 7541 5.2. A string literal: an H flag (1 bit), a
 * length as a 7-bit prefixed integer, then that many octets. H=0 octets are
 * copied raw; H=1 octets are the static Huffman code and are decoded (RFC
 * 7541 Appendix B). The H flag is the high bit of the length's prefix byte. */

/* Encode src as a raw (H=0) string literal into buf. Returns bytes written,
 * or 0 if it does not fit. */
usz quic_qpack_string_encode(quic_mspan buf, quic_span src);

/* Decode a string literal at buf into dst, setting dst->len. H=1 values are
 * Huffman-decoded. Returns bytes consumed, or 0 on truncation, a Huffman
 * decode error, or dst overflow. */
usz quic_qpack_string_decode(quic_span buf, quic_obuf *dst);

#endif
