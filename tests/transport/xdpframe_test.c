#include "test.h"

/* Hand-assembled 60-byte frame: 10.7.0.2:5555 -> 10.7.0.1:4433, payload
 * "hi", padded to the ethernet minimum frame size. The IP and UDP checksum
 * fields are left zero on purpose: the parser must not verify them. */
static const u8 xdpft_golden[60] = {
    0x02, 0x07, 0x00, 0x00, 0x00, 0x01, /* eth dst (our mac) */
    0x02, 0x07, 0x00, 0x00, 0x00, 0x02, /* eth src (peer mac) */
    0x08, 0x00,                         /* ethertype IPv4 */
    0x45, 0x00, 0x00, 0x1e,             /* ip: v4 IHL=5, total 30 */
    0x00, 0x00, 0x00, 0x00,             /* id, flags/frag = 0 */
    0x40, 0x11, 0x00, 0x00,             /* ttl, proto UDP, cksum 0 */
    10,   7,    0,    2,                /* ip src 10.7.0.2 */
    10,   7,    0,    1,                /* ip dst 10.7.0.1 */
    0x15, 0xb3, 0x11, 0x51,             /* udp sport 5555, dport 4433 */
    0x00, 0x0a, 0x00, 0x00,             /* udp len 10, cksum 0 */
    'h',  'i',                          /* payload */
    0,    0,    0,    0,    0,    0,    /* eth minimum-frame padding */
    0,    0,    0,    0,    0,    0,    0, 0, 0, 0};

static u16 xdpft_ntoh16(u16 v) { return (u16)((v >> 8) | (v << 8)); }

static int xdpft_mac_eq(const u8* a, const u8* b) {
  for (usz i = 0; i < 6; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* The golden frame parses to the peer sockaddr, both MACs, our ip/port and
 * the payload view. */
static void test_xdpframe_rx_golden(void) {
  quic_xdpframe_rx rx;
  quic_sockaddr    want_src, want_dst;
  wired_udp_addr(&want_src, 5555, (const u8[]){10, 7, 0, 2});
  wired_udp_addr(&want_dst, 4433, (const u8[]){10, 7, 0, 1});
  CHECK(quic_xdpframe_parse(quic_span_of(xdpft_golden, 60), &rx) == 1);
  CHECK(rx.src.family == want_src.family);
  CHECK(rx.src.port_be == want_src.port_be);
  CHECK(quic_ct_diffn(rx.src.addr, want_src.addr, 16) == 0);
  CHECK(xdpft_mac_eq(rx.peer_mac, xdpft_golden + 6));
  CHECK(xdpft_mac_eq(rx.our_mac, xdpft_golden));
  CHECK(rx.our_ip == wired_udp_addr4_be(&want_dst));
  CHECK(rx.dport == 4433);
  CHECK(rx.payload == xdpft_golden + QUIC_XDPFRAME_HDRS);
  CHECK(rx.payload_len == 2 && rx.payload[0] == 'h' && rx.payload[1] == 'i');
}

/* 1 iff a copy of the golden frame with byte off set to val, truncated to n
 * bytes, is rejected. */
static int xdpft_rejects(usz n, usz off, u8 val) {
  u8               f[60];
  quic_xdpframe_rx rx;
  for (usz i = 0; i < 60; i++) f[i] = xdpft_golden[i];
  f[off] = val;
  return quic_xdpframe_parse(quic_span_of(f, n), &rx) == 0;
}

static void test_xdpframe_rx_rejects(void) {
  CHECK(xdpft_rejects(QUIC_XDPFRAME_HDRS - 1, 0, 0x02)); /* short */
  CHECK(xdpft_rejects(60, 13, 0x06));                    /* ethertype ARP */
  CHECK(xdpft_rejects(60, 14, 0x46));                    /* IHL != 5 */
  CHECK(xdpft_rejects(60, 20, 0x20));                    /* MF fragment bit */
  CHECK(xdpft_rejects(60, 23, 6));                       /* protocol TCP */
  CHECK(xdpft_rejects(60, 39, 0x0b)); /* udp len != ip total - 20 */
  CHECK(xdpft_rejects(60, 16, 0x01)); /* ip total beyond the frame */
}

/* A built frame satisfies the independent net/ verifiers and carries the
 * payload at the fixed offset; a too-small buffer is refused. */
static void test_xdpframe_tx_roundtrip(void) {
  u8                     buf[128];
  const u8               pl[3] = {0xc0, 0xff, 0xee};
  const quic_xdpframe_tx m     = {
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x02},
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x01},
      {{4433, 5555}, {0x0a070001, 0x0a070002}}};
  quic_eth_head    eh;
  quic_xdpframe_rx rx;
  usz              n = quic_xdpframe_build(
      quic_mspan_of(buf, sizeof(buf)), &m, quic_span_of(pl, 3));
  CHECK(n == QUIC_XDPFRAME_HDRS + 3);
  CHECK(quic_eth_parse(quic_span_of(buf, n), &eh) == 1);
  CHECK(eh.ethertype == QUIC_ETH_TYPE_IPV4);
  CHECK(xdpft_mac_eq(eh.dst, m.dst_mac) && xdpft_mac_eq(eh.src, m.src_mac));
  CHECK(quic_ipv4_check(buf + QUIC_ETH_HDR) == 1);
  CHECK(
      quic_udp4_check(
          quic_span_of(buf + QUIC_ETH_HDR + QUIC_IPV4_HDR, QUIC_UDP_HDR + 3),
          m.udp.addrs) == 1);
  CHECK(buf[QUIC_XDPFRAME_HDRS] == 0xc0 && buf[QUIC_XDPFRAME_HDRS + 2] == 0xee);
  CHECK(quic_xdpframe_parse(quic_span_of(buf, n), &rx) == 1);
  CHECK(rx.dport == 5555 && rx.payload_len == 3);
  CHECK(
      quic_xdpframe_build(
          quic_mspan_of(buf, QUIC_XDPFRAME_HDRS + 2), &m,
          quic_span_of(pl, 3)) == 0);
}

/* Parsing the golden frame and reflecting its fields into a reply swaps the
 * roles exactly: the reply's peer is our old address and vice versa. */
static void test_xdpframe_reflect(void) {
  quic_xdpframe_rx rx, rr;
  quic_xdpframe_tx m;
  quic_sockaddr    want_src, want_peer;
  u8               buf[64];
  const u8         pl[2] = {'y', 'o'};
  CHECK(quic_xdpframe_parse(quic_span_of(xdpft_golden, 60), &rx) == 1);
  for (usz i = 0; i < 6; i++) m.dst_mac[i] = rx.peer_mac[i];
  for (usz i = 0; i < 6; i++) m.src_mac[i] = rx.our_mac[i];
  m.udp.ports.sport = rx.dport;
  m.udp.ports.dport = xdpft_ntoh16(rx.src.port_be);
  m.udp.addrs.src   = rx.our_ip;
  m.udp.addrs.dst   = wired_udp_addr4_be(&rx.src);
  usz n             = quic_xdpframe_build(
      quic_mspan_of(buf, sizeof(buf)), &m, quic_span_of(pl, 2));
  CHECK(n == QUIC_XDPFRAME_HDRS + 2);
  CHECK(quic_xdpframe_parse(quic_span_of(buf, n), &rr) == 1);
  wired_udp_addr(&want_src, 4433, (const u8[]){10, 7, 0, 1});
  wired_udp_addr(&want_peer, 5555, (const u8[]){10, 7, 0, 2});
  CHECK(rr.src.port_be == want_src.port_be);
  CHECK(quic_ct_diffn(rr.src.addr, want_src.addr, 16) == 0);
  CHECK(rr.dport == 5555 && rr.our_ip == wired_udp_addr4_be(&want_peer));
  CHECK(xdpft_mac_eq(rr.peer_mac, rx.our_mac));
  CHECK(xdpft_mac_eq(rr.our_mac, rx.peer_mac));
  CHECK(rr.payload_len == 2 && rr.payload[0] == 'y');
}

void test_xdpframe(void) {
  test_xdpframe_rx_golden();
  test_xdpframe_rx_rejects();
  test_xdpframe_tx_roundtrip();
  test_xdpframe_reflect();
}
