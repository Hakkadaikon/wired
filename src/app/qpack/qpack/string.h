#ifndef QUIC_QPACK_STRING_H
#define QUIC_QPACK_STRING_H

#include "common/platform/sys/syscall.h"

/* RFC 9204 4.1.2 / RFC 7541 5.2. A string literal: an H flag (1 bit), a
 * length as a 7-bit prefixed integer, then that many octets. H=0 octets are
 * copied raw; H=1 octets are the static Huffman code and are decoded (RFC
 * 7541 Appendix B). The H flag is the high bit of the length's prefix byte. */

/* Encode src (len octets) as a raw (H=0) string literal into buf of cap
 * bytes. Returns bytes written, or 0 if it does not fit. */
usz quic_qpack_string_encode(u8 *buf, usz cap, const u8 *src, usz len);

/* Decode a string literal at buf (n bytes) into dst (dcap octets), setting
 * *out_len. H=1 values are Huffman-decoded. Returns bytes consumed, or 0 on
 * truncation, a Huffman decode error, or dst overflow. */
usz quic_qpack_string_decode(
    const u8 *buf, usz n, u8 *dst, usz dcap, usz *out_len);

#endif
