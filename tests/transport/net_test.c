#include "test.h"

/* RFC 1071 worked example: the bytes 00 01 f2 03 f4 f5 f6 f7 fold to the
 * sum 0xddf2, whose one's complement (the checksum field) is 0x220d. */
static void test_checksum_rfc1071(void) {
  const u8 d[8] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
  CHECK(quic_cksum(d, 8) == 0x220d);
}

/* A built IPv4 header verifies; flipping a byte breaks verification. */
static void test_ipv4_checksum(void) {
  u8 hdr[QUIC_IPV4_HDR];
  quic_ipv4_build(
      hdr, &(quic_ipv4_head){1200, 0x7f000001, 0x7f000002, QUIC_IP_PROTO_UDP});
  CHECK(hdr[0] == 0x45 && hdr[9] == QUIC_IP_PROTO_UDP);
  CHECK(quic_ipv4_check(hdr) == 1);
  hdr[12] ^= 0x01;
  CHECK(quic_ipv4_check(hdr) == 0);
}

/* A built UDP datagram verifies under its pseudo-header; tamper breaks it. */
static void test_udp_checksum(void) {
  u8             dg[64];
  const u8       pl[]  = {0xde, 0xad, 0xbe, 0xef};
  quic_ipv4addrs addrs = {0x7f000001, 0x7f000002};
  quic_udp4meta  meta  = {{0x1234, 0x4321}, addrs};
  quic_obuf      ob    = quic_obuf_of(dg, sizeof(dg));
  usz            n     = quic_udp4_build(&ob, &meta, quic_span_of(pl, 4));
  CHECK(n == QUIC_UDP_HDR + 4);
  CHECK(quic_udp4_check(quic_span_of(dg, n), addrs) == 1);
  dg[QUIC_UDP_HDR + 1] ^= 0x10;
  CHECK(quic_udp4_check(quic_span_of(dg, n), addrs) == 0);
}

/* The in-memory link carries datagrams FIFO with no syscalls. */
static void test_memlink_fifo(void) {
  quic_memlink l;
  quic_memlink_init(&l);
  CHECK(quic_memlink_send(&l, (const u8*)"first", 5) == 1);
  CHECK(quic_memlink_send(&l, (const u8*)"second", 6) == 1);
  u8 out[16];
  CHECK(quic_memlink_recv(&l, out, sizeof(out)) == 5 && out[0] == 'f');
  CHECK(quic_memlink_recv(&l, out, sizeof(out)) == 6 && out[0] == 's');
  CHECK(quic_memlink_recv(&l, out, sizeof(out)) == 0);
}

/* A full IPv4+UDP datagram travels across the link and verifies intact. */
static void test_net_datagram_over_link(void) {
  u8             ip[QUIC_IPV4_HDR], udp[64], frame[QUIC_IPV4_HDR + 64];
  const u8       pl[]  = {1, 2, 3, 4, 5};
  quic_ipv4addrs addrs = {0x0a000001, 0x0a000002};
  quic_udp4meta  meta  = {{9000, 443}, addrs};
  quic_obuf      ub    = quic_obuf_of(udp, sizeof(udp));
  usz            un    = quic_udp4_build(&ub, &meta, quic_span_of(pl, 5));
  quic_ipv4_build(
      ip, &(quic_ipv4_head){(u16)(QUIC_IPV4_HDR + un), 0x0a000001, 0x0a000002,
                            QUIC_IP_PROTO_UDP});
  for (usz i = 0; i < QUIC_IPV4_HDR; i++) frame[i] = ip[i];
  for (usz i = 0; i < un; i++) frame[QUIC_IPV4_HDR + i] = udp[i];

  quic_memlink l;
  quic_memlink_init(&l);
  quic_memlink_send(&l, frame, QUIC_IPV4_HDR + un);
  u8  rx[QUIC_IPV4_HDR + 64];
  usz rn = quic_memlink_recv(&l, rx, sizeof(rx));
  CHECK(rn == QUIC_IPV4_HDR + un);
  CHECK(quic_ipv4_check(rx) == 1);
  CHECK(quic_udp4_check(quic_span_of(rx + QUIC_IPV4_HDR, un), addrs) == 1);
  CHECK(rx[QUIC_IPV4_HDR + QUIC_UDP_HDR + 4] == 5); /* payload intact */
}

void test_net(void) {
  test_checksum_rfc1071();
  test_ipv4_checksum();
  test_udp_checksum();
  test_memlink_fifo();
  test_net_datagram_over_link();
}
