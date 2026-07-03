#include "test.h"

/* sockaddr_in is laid out big-endian for the kernel. */
static void test_udp_addr_layout(void) {
  quic_sockaddr_in sa;
  wired_udp_addr(&sa, 443, (const u8[4]){127, 0, 0, 1});
  CHECK(sa.family == WIRED_AF_INET);
  /* port 443 = 0x01BB -> network order 0xBB01 on a little-endian host */
  CHECK(sa.port_be == 0xBB01);
  /* 127.0.0.1 = 0x7F000001 -> network order bytes 7F 00 00 01;
   * as a little-endian u32 that reads back 0x0100007F */
  CHECK(sa.addr_be == 0x0100007F);
}

/* The two byte-swaps are inverses of a known constant. */
static void test_udp_hton(void) {
  CHECK(hton16(0x1234) == 0x3412);
  CHECK(hton32(0x11223344) == 0x44332211);
}

void test_udp(void) {
  test_udp_addr_layout();
  test_udp_hton();
}
