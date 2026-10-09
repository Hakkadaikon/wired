#define WIRED_MAIN
#include "wired.h"

int wired_main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  static const u8 lo[4] = {127, 0, 0, 1};
  sockaddr        a, b, from;
  wired_udp_addr(&a, 14512, lo);
  wired_udp_addr(&b, 14513, lo);

  i64 sa = wired_udp_socket();
  i64 sb = wired_udp_socket();
  if (wired_udp_bind(sa, &a) < 0 || wired_udp_bind(sb, &b) < 0) return 1;

  /* a -> b, then b reads it along with the sender's address. */
  wired_udp_send(sa, &b, wired_span_cstr("hello"));
  u8  buf[64];
  i64 n = wired_udp_recvfrom(sb, wired_mspan_of(buf, sizeof buf - 1), &from);
  if (n < 0) return 1;
  buf[n] = 0;

  u16 port =
      (u16)((from.port_be >> 8) | (from.port_be << 8)); /* to host order */
  wired_dprintf(
      2, "recv %llu bytes: %s from %llu\n", (u64)n, (const char*)buf,
      (u64)port);

  wired_udp_close(sa);
  wired_udp_close(sb);
  return 0;
}
