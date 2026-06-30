#include "test.h"

/* The 3-byte length is read big-endian, and a message is complete only once
 * buffered covers the 4-byte header plus the declared body. */
void test_msgassembly(void) {
  /* big-endian 3-byte length */
  u8 h[4] = {20, 0x01, 0x02, 0x03};
  CHECK(quic_tls_message_len(h) == 0x010203u);

  u8 z[4] = {1, 0, 0, 0};
  CHECK(quic_tls_message_len(z) == 0);

  /* boundary: header(4) + declared(10) == 14 */
  CHECK(quic_tls_message_complete(13, 10) == 0);
  CHECK(quic_tls_message_complete(14, 10) != 0);
  CHECK(quic_tls_message_complete(15, 10) != 0);

  /* zero-length body still needs its 4-byte header */
  CHECK(quic_tls_message_complete(3, 0) == 0);
  CHECK(quic_tls_message_complete(4, 0) != 0);

  /* near u32 max length must not wrap when adding 4 */
  CHECK(quic_tls_message_complete(0xFFFFFFFFull, 0xFFFFFFFFu) == 0);
  CHECK(quic_tls_message_complete(0x100000003ull, 0xFFFFFFFFu) != 0);
}
