#include "test.h"

/* The server reflects the peer's spin; the client inverts it. */
static void test_spin_roles(void) {
  CHECK(quic_spin_outgoing(1, 0) == 0); /* server reflects 0 */
  CHECK(quic_spin_outgoing(1, 1) == 1); /* server reflects 1 */
  CHECK(quic_spin_outgoing(0, 0) == 1); /* client inverts 0 */
  CHECK(quic_spin_outgoing(0, 1) == 0); /* client inverts 1 */
}

/* The spin bit reads back from and writes into a short-header first byte. */
static void test_spin_byte(void) {
  u8 b = 0x40; /* short header fixed bit, spin clear */
  CHECK(quic_spin_get(b) == 0);
  u8 set = quic_spin_set(b, 1);
  CHECK(quic_spin_get(set) == 1 && (set & 0x40) == 0x40); /* other bits kept */
  CHECK(quic_spin_get(quic_spin_set(set, 0)) == 0);
}

/* A client-server exchange flips the bit once per round trip. */
static void test_spin_cycle(void) {
  int spin       = 0;                                 /* start of round */
  int client_out = quic_spin_outgoing(0, spin);       /* client inverts -> 1 */
  int server_out = quic_spin_outgoing(1, client_out); /* server reflects -> 1 */
  int next       = quic_spin_outgoing(0, server_out); /* client inverts -> 0 */
  CHECK(client_out == 1 && server_out == 1 && next == 0); /* back to start */
}

void test_spin(void) {
  test_spin_roles();
  test_spin_byte();
  test_spin_cycle();
}
