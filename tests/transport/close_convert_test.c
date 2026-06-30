#include "test.h"

/* RFC 9000 10.2.3: only an application close during the handshake converts. */
static void test_close_needs_convert_matrix(void) {
  CHECK(quic_close_needs_convert(1, 1) == 1); /* app close in handshake */
  CHECK(quic_close_needs_convert(1, 0) == 0); /* app close, post-handshake */
  CHECK(quic_close_needs_convert(0, 1) == 0); /* transport close in handshake */
  CHECK(quic_close_needs_convert(0, 0) == 0); /* transport close otherwise */
}

/* Conversion always targets the transport close type 0x1c. */
static void test_close_converted_type(void) {
  CHECK(quic_close_converted_type() == 0x1c);
  CHECK(quic_close_converted_type() != QUIC_CLOSE_APPLICATION);
}

void test_close_convert(void) {
  test_close_needs_convert_matrix();
  test_close_converted_type();
}
