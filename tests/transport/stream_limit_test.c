#include "test.h"

/* RFC 9000 4.6: a max_streams of N permits indices 0..N-1; the highest stream
 * ID is the ID of index N-1 for the selected type. */
void test_stream_limit(void) {
  u64 id;

  /* zero streams permitted: no valid maximum */
  CHECK(quic_stream_max_id(0, 0, 0, &id) == 0);

  /* client bidi, max_streams 1: only index 0 -> stream ID 0 */
  CHECK(quic_stream_max_id(0, 0, 1, &id) == 1);
  CHECK(id == 0);

  /* client bidi, max_streams 5: index 4 -> ID 16 (4 << 2) */
  CHECK(quic_stream_max_id(0, 0, 5, &id) == 1);
  CHECK(id == 16);

  /* server uni, max_streams 1: index 0 -> low bits 0b11 = 3 */
  CHECK(quic_stream_max_id(1, 1, 1, &id) == 1);
  CHECK(id == 3);

  /* client uni, max_streams 3: index 2 -> (2<<2)|0b10 = 10 */
  CHECK(quic_stream_max_id(0, 1, 3, &id) == 1);
  CHECK(id == 10);

  /* the legal limit boundary: 2^60 is allowed, 2^60 + 1 is not */
  CHECK(quic_stream_max_streams_ok(((u64)1) << 60) == 1);
  CHECK(quic_stream_max_streams_ok((((u64)1) << 60) + 1) == 0);
  CHECK(quic_stream_max_id(0, 0, (((u64)1) << 60) + 1, &id) == 0);
}
