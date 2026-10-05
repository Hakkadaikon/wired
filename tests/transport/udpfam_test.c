#include "test.h"

/* 12-24: the AF_INET fallback for IPv6-less hosts. Callers always hold the
 * v4-mapped sockaddr (udp.h); udp.c converts it to the socket's family at
 * the syscall boundary (RFC 4291 2.5.5.2 mapping, uapi in.h/in6.h layouts). */

/* AF_INET6: the address goes to the kernel unchanged, 28 bytes. */
static void test_udpfam_out_v6_copies(void) {
  sockaddr sa, k;
  wired_udp_addr(&sa, 4433, (const u8[4]){127, 0, 0, 1});
  CHECK(udp_kaddr_out(&sa, WIRED_AF_INET6, &k) == 28);
  CHECK(k.family == WIRED_AF_INET6 && k.port_be == sa.port_be);
  for (usz i = 0; i < 16; i++) CHECK(k.addr[i] == sa.addr[i]);
}

/* AF_INET: sockaddr_in = family 2, port, a.b.c.d at byte 4, 8 zero bytes. */
static void test_udpfam_out_v4_packs(void) {
  sockaddr sa, k;
  const u8 want[16] = {2, 0, 0x11, 0x51, 192, 168, 1, 20};
  wired_udp_addr(&sa, 4433, (const u8[4]){192, 168, 1, 20});
  CHECK(udp_kaddr_out(&sa, WIRED_AF_INET, &k) == 16);
  for (usz i = 0; i < 16; i++) CHECK(((const u8*)&k)[i] == want[i]);
}

/* The dual-stack any-address :: packs to 0.0.0.0 (bind any). */
static void test_udpfam_out_v4_any(void) {
  sockaddr sa, k;
  wired_udp_addr(&sa, 443, (const u8[4]){0, 0, 0, 0});
  CHECK(udp_kaddr_out(&sa, WIRED_AF_INET, &k) == 16);
  for (usz i = 4; i < 16; i++) CHECK(((const u8*)&k)[i] == 0);
}

/* A kernel-written sockaddr_in reads back as the v4-mapped form. */
static void test_udpfam_in_v4_maps(void) {
  sockaddr sa, want, k;
  wired_udp_addr(&want, 4433, (const u8[4]){10, 0, 0, 7});
  udp_kaddr_out(&want, WIRED_AF_INET, &k);
  sa = k;
  udp_kaddr_in(&sa);
  CHECK(sa.family == WIRED_AF_INET6 && sa.port_be == want.port_be);
  CHECK(sa.flowinfo == 0 && sa.scope_id == 0);
  for (usz i = 0; i < 16; i++) CHECK(sa.addr[i] == want.addr[i]);
}

/* A raw kernel sockaddr_in (what getsockname returns on an AF_INET fd) is
 * accepted as input in both families. */
static void test_udpfam_out_accepts_raw_v4(void) {
  sockaddr want, raw, k;
  wired_udp_addr(&want, 4433, (const u8[4]){127, 0, 0, 1});
  udp_kaddr_out(&want, WIRED_AF_INET, &raw);
  CHECK(udp_kaddr_out(&raw, WIRED_AF_INET, &k) == 16);
  for (usz i = 0; i < 16; i++) CHECK(((u8*)&k)[i] == ((u8*)&raw)[i]);
  CHECK(udp_kaddr_out(&raw, WIRED_AF_INET6, &k) == 28);
  for (usz i = 0; i < 16; i++) CHECK(k.addr[i] == want.addr[i]);
}

/* An AF_INET6 source is left exactly as the kernel wrote it. */
static void test_udpfam_in_v6_untouched(void) {
  sockaddr sa;
  wired_udp_addr(&sa, 443, (const u8[4]){9, 9, 9, 9});
  sa.addr[0] = 0x20; /* native IPv6, not v4-mapped */
  udp_kaddr_in(&sa);
  CHECK(sa.family == WIRED_AF_INET6 && sa.addr[0] == 0x20);
  CHECK(wired_udp_addr4_be(&sa) == 0x09090909);
}

/* Loopback round trip on whichever family this host supports: bind
 * 127.0.0.1:0 is not portable to learn the port without getsockname, so
 * bind a fixed high port; the source must come back v4-mapped. A failed
 * socket()/bind() (sandbox, port in use) is a benign skip. */
static void test_udpfam_loopback_roundtrip(void) {
  sockaddr a, src = {0};
  u8       out[3] = {1, 2, 3}, in[8];
  i64      fd     = wired_udp_socket();
  if (fd < 0) return;
  wired_udp_addr(&a, 47913, (const u8[4]){127, 0, 0, 1});
  if (wired_udp_bind(fd, &a) == 0) {
    CHECK(wired_udp_send(fd, &a, wired_span_of(out, 3)) == 3);
    CHECK(wired_udp_recvfrom(fd, wired_mspan_of(in, sizeof in), &src) == 3);
    CHECK(src.family == WIRED_AF_INET6 && src.port_be == a.port_be);
    CHECK(wired_udp_addr4_be(&src) == 0x7f000001 && src.addr[10] == 0xff);
  }
  wired_udp_close(fd);
}

void test_udpfam(void) {
  test_udpfam_out_v6_copies();
  test_udpfam_out_v4_packs();
  test_udpfam_out_v4_any();
  test_udpfam_in_v4_maps();
  test_udpfam_out_accepts_raw_v4();
  test_udpfam_in_v6_untouched();
  test_udpfam_loopback_roundtrip();
}
