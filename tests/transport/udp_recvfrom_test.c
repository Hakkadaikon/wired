#include "test.h"

/* No real socket: recvfrom on a bad fd must fail without touching src. */
static void test_recvfrom_badfd(void) {
  quic_sockaddr_in src;
  wired_udp_addr(
      &src, 443,
      (const u8[4]){9, 9, 9, 9}); /* sentinel the kernel must not need */
  u8  buf[16];
  i64 r = wired_udp_recvfrom(-1, quic_mspan_of(buf, sizeof buf), &src);
  /* EBADF (-9) on Linux; any negative errno is acceptable. */
  CHECK(r < 0);
  /* Failed recvfrom leaves the sentinel intact. */
  CHECK(src.family == QUIC_AF_INET);
  CHECK(src.addr_be == 0x09090909);
}

/* close wrapper links and rejects a bad fd with a negative errno. */
static void test_close_badfd(void) { CHECK(wired_udp_close(-1) < 0); }

void test_udp_recvfrom(void) {
  test_recvfrom_badfd();
  test_close_badfd();
}
