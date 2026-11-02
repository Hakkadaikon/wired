#ifndef QPACK_HUFFMAN_H
#define QPACK_HUFFMAN_H

#include "common/bytes/span/span.h"

/* RFC 7541 Appendix B / RFC 9204 4.1.2. Decode a Huffman-coded (H=1) string
 * literal's octets. src holds the canonical static Huffman code; the decoded
 * bytes go to dst, with the count in dst->len.
 *
 * Returns 1 on success, 0 on: dst overflow, an EOS symbol in the stream,
 * a padding of 8 or more bits, or a final padding that is not all-ones
 * (RFC 7541 5.2). */
int qpack_huffman_decode(wired_span src, wired_obuf* dst);

/* RFC 7541 Appendix B / 5.2. Huffman-code src into dst, padding the last
 * octet with the most significant bits of EOS (all ones). Returns the coded
 * length in octets; only the first dst.n of them are written, so an empty
 * dst just sizes the code. */
usz qpack_huffman_encode(wired_span src, wired_mspan dst);

#endif
