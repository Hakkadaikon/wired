#ifndef QUIC_QPACK_HUFFMAN_H
#define QUIC_QPACK_HUFFMAN_H

#include "common/platform/sys/syscall.h"

/* RFC 7541 Appendix B / RFC 9204 4.1.2. Decode a Huffman-coded (H=1) string
 * literal's octets. src (src_len bytes) holds the canonical static Huffman
 * code; the decoded bytes go to dst (dcap), with the count in *out_len.
 *
 * Returns 1 on success, 0 on: dst overflow, an EOS symbol in the stream,
 * a padding of 8 or more bits, or a final padding that is not all-ones
 * (RFC 7541 5.2). */
int quic_qpack_huffman_decode(
    const u8 *src, usz src_len, u8 *dst, usz dcap, usz *out_len);

#endif
