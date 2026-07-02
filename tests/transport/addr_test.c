#include "test.h"

/* Octets pack into a big-endian u32: a is the most significant byte. */
static void test_addr_from_octets(void) {
  CHECK(quic_addr_from_octets((const u8[4]){127, 0, 0, 1}) == 0x7F000001u);
  CHECK(quic_addr_from_octets((const u8[4]){192, 168, 1, 254}) == 0xC0A801FEu);
  CHECK(quic_addr_from_octets((const u8[4]){0, 0, 0, 0}) == 0u);
  CHECK(
      quic_addr_from_octets((const u8[4]){255, 255, 255, 255}) ==
      0xFFFFFFFFu);
}

/* to_octets is the inverse of from_octets. */
static void test_addr_roundtrip(void) {
  u8 o[4];
  quic_addr_to_octets(quic_addr_from_octets((const u8[4]){10, 20, 30, 40}), o);
  CHECK(o[0] == 10 && o[1] == 20 && o[2] == 30 && o[3] == 40);

  quic_addr_to_octets(0x7F000001u, o);
  CHECK(o[0] == 127 && o[1] == 0 && o[2] == 0 && o[3] == 1);
}

/* port_be swaps the two bytes (big-endian on a little-endian host). */
static void test_port_be(void) {
  CHECK(quic_port_be(443) == 0xBB01);
  CHECK(quic_port_be(0x1234) == 0x3412);
}

void test_addr(void) {
  test_addr_from_octets();
  test_addr_roundtrip();
  test_port_be();
}
