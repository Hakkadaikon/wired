#include "test.h"

/* RFC 9287 3.1: a client greases early only when it remembers the server
 * advertised grease_quic_bit. */
static void test_early_client(void) {
  CHECK(quic_greasebit_client_early_ok(0) == 0);
  CHECK(quic_greasebit_client_early_ok(1) == 1);
}

/* RFC 9287 3.1: a server greases only after processing the client's TPs and
 * advertising grease_quic_bit itself. */
static void test_early_server(void) {
  CHECK(quic_greasebit_server_ok(0, 0) == 0);
  CHECK(quic_greasebit_server_ok(1, 0) == 0);
  CHECK(quic_greasebit_server_ok(0, 1) == 0);
  CHECK(quic_greasebit_server_ok(1, 1) == 1);
}

void test_early(void) {
  test_early_client();
  test_early_server();
}
