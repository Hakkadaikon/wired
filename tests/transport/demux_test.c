#include "test.h"

/* RFC 9000 5.1/5.2 CID demux: exact match, mismatch, length mismatch, and
 * zero-length CID handling. */
void test_demux(void) {
  const u8 a[] = {0xDE, 0xAD, 0xBE, 0xEF};
  const u8 b[] = {0xDE, 0xAD, 0xBE, 0xEF};
  const u8 c[] = {0xDE, 0xAD, 0xBE, 0x00};
  const u8 d[] = {0xDE, 0xAD, 0xBE}; /* shorter */

  CHECK(quic_demux_match(quic_span_of(a, 4), quic_span_of(b, 4)) == 1); /* same bytes + length */
  CHECK(quic_demux_match(quic_span_of(a, 4), quic_span_of(c, 4)) == 0); /* last byte differs */
  CHECK(quic_demux_match(quic_span_of(a, 4), quic_span_of(d, 3)) == 0); /* length differs */

  /* zero-length CIDs match each other but not a non-empty one */
  CHECK(quic_demux_match(quic_span_of(0, 0), quic_span_of(0, 0)) == 1);
  CHECK(quic_demux_match(quic_span_of(a, 4), quic_span_of(0, 0)) == 0);
  CHECK(quic_demux_match(quic_span_of(0, 0), quic_span_of(a, 4)) == 0);
}
