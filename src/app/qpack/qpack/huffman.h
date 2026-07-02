#ifndef QUIC_QPACK_HUFFMAN_H
#define QUIC_QPACK_HUFFMAN_H

#include "common/bytes/span/span.h"

/* RFC 7541 Appendix B / RFC 9204 4.1.2. Decode a Huffman-coded (H=1) string
 * literal's octets. src holds the canonical static Huffman code; the decoded
 * bytes go to dst, with the count in dst->len.
 *
 * Returns 1 on success, 0 on: dst overflow, an EOS symbol in the stream,
 * a padding of 8 or more bits, or a final padding that is not all-ones
 * (RFC 7541 5.2). */
int quic_qpack_huffman_decode(quic_span src, quic_obuf *dst);

#endif
