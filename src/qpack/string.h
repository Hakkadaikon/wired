#ifndef QUIC_QPACK_STRING_H
#define QUIC_QPACK_STRING_H

#include "sys/syscall.h"

/* RFC 9204 4.1.2 / RFC 7541 5.2. A string literal: an H flag (1 bit), a
 * length as a 7-bit prefixed integer, then that many octets. Only raw
 * (H=0) is implemented; a decoded H=1 (Huffman) string is rejected. The
 * H flag is the high bit of the length's prefix byte. */

/* Encode src (len octets) as a raw (H=0) string literal into buf of cap
 * bytes. Returns bytes written, or 0 if it does not fit. */
usz quic_qpack_string_encode(u8 *buf, usz cap, const u8 *src, usz len);

/* Decode a string literal at buf (n bytes) into dst (dcap octets), setting
 * *out_len. Returns bytes consumed, or 0 on truncation, Huffman (H=1, not
 * supported), or dst overflow. */
usz quic_qpack_string_decode(const u8 *buf, usz n, u8 *dst, usz dcap,
                             usz *out_len);

#endif
