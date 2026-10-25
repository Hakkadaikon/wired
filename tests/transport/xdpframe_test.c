#include "test.h"

/* Hand-assembled 60-byte frame: 10.7.0.2:5555 -> 10.7.0.1:4433, payload
 * "hi", padded to the ethernet minimum frame size. The IP header checksum
 * 0x66bf is hand-computed (RFC 1071 sum 0x9940); the UDP checksum is zero,
 * RFC 768's "no checksum generated". */
static const u8 xdpft_golden[60] = {
    0x02, 0x07, 0x00, 0x00, 0x00, 0x01, /* eth dst (our mac) */
    0x02, 0x07, 0x00, 0x00, 0x00, 0x02, /* eth src (peer mac) */
    0x08, 0x00,                         /* ethertype IPv4 */
    0x45, 0x00, 0x00, 0x1e,             /* ip: v4 IHL=5, total 30 */
    0x00, 0x00, 0x00, 0x00,             /* id, flags/frag = 0 */
    0x40, 0x11, 0x66, 0xbf,             /* ttl, proto UDP, cksum */
    10,   7,    0,    2,                /* ip src 10.7.0.2 */
    10,   7,    0,    1,                /* ip dst 10.7.0.1 */
    0x15, 0xb3, 0x11, 0x51,             /* udp sport 5555, dport 4433 */
    0x00, 0x0a, 0x00, 0x00,             /* udp len 10, cksum 0 */
    'h',  'i',                          /* payload */
    0,    0,    0,    0,    0,    0,    /* eth minimum-frame padding */
    0,    0,    0,    0,    0,    0,    0, 0, 0, 0};

static u16 xdpft_ntoh16(u16 v) { return (u16)((v >> 8) | (v << 8)); }

static int xdpft_mac_eq(const u8* a, const u8* b) {
  for (usz i = 0; i < 6; i++) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}

/* The golden frame parses to the peer sockaddr, both MACs, our ip/port and
 * the payload view. */
static void test_xdpframe_rx_golden(void) {
  xdpframe_rx rx;
  sockaddr    want_src, want_dst;
  wired_udp_addr(&want_src, 5555, (const u8[]){10, 7, 0, 2});
  wired_udp_addr(&want_dst, 4433, (const u8[]){10, 7, 0, 1});
  CHECK(xdpframe_parse(wired_span_of(xdpft_golden, 60), 0, &rx) == 1);
  CHECK(rx.src.family == want_src.family);
  CHECK(rx.src.port_be == want_src.port_be);
  CHECK(ct_diffn(rx.src.addr, want_src.addr, 16) == 0);
  CHECK(xdpft_mac_eq(rx.peer_mac, xdpft_golden + 6));
  CHECK(xdpft_mac_eq(rx.our_mac, xdpft_golden));
  CHECK(rx.our_ip == wired_udp_addr4_be(&want_dst));
  CHECK(rx.dport == 4433);
  CHECK(rx.payload == xdpft_golden + XDPFRAME_HDRS);
  CHECK(rx.payload_len == 2 && rx.payload[0] == 'h' && rx.payload[1] == 'i');
}

/* Copy the golden frame into f with byte off set to val, then refill the IP
 * header checksum so only the mutated field can cause a rejection. */
static void xdpft_mutate(u8 f[60], usz off, u8 val) {
  for (usz i = 0; i < 60; i++) {
    f[i] = xdpft_golden[i];
  }
  f[off]          = val;
  f[ETH_HDR + 10] = 0;
  f[ETH_HDR + 11] = 0;
  u16 c           = cksum(f + ETH_HDR, (usz)(f[ETH_HDR] & 0x0f) * 4);
  f[ETH_HDR + 10] = (u8)(c >> 8);
  f[ETH_HDR + 11] = (u8)c;
}

/* 1 iff a copy of the golden frame with byte off set to val (checksum
 * refilled), truncated to n bytes, is rejected under flags. */
static int xdpft_rejects_f(usz n, usz off, u8 val, u32 flags) {
  u8          f[60];
  xdpframe_rx rx;
  xdpft_mutate(f, off, val);
  return xdpframe_parse(wired_span_of(f, n), flags, &rx) == 0;
}

static int xdpft_rejects(usz n, usz off, u8 val) {
  return xdpft_rejects_f(n, off, val, 0);
}

/* 1 iff the golden frame with byte off XORed by x (checksum NOT refilled)
 * is rejected under flags. */
static int xdpft_rejects_raw(usz off, u8 x, u32 flags) {
  u8          f[60];
  xdpframe_rx rx;
  for (usz i = 0; i < 60; i++) {
    f[i] = xdpft_golden[i];
  }
  f[off] ^= x;
  return xdpframe_parse(wired_span_of(f, 60), flags, &rx) == 0;
}

/* RFC 791 3.1 / 1.4: a header whose checksum fails is discarded, wherever
 * the bit flip lands (checksum field, address, TTL); the UDP-checksum
 * opt-out does not relax it. */
static void test_xdpframe_rx_rejects_bad_ip_checksum(void) {
  CHECK(xdpft_rejects_raw(ETH_HDR + 10, 0x01, 0));
  CHECK(xdpft_rejects_raw(ETH_HDR + 12, 0x80, 0));
  CHECK(xdpft_rejects_raw(ETH_HDR + 8, 0x01, XDPFRAME_SKIP_UDP_CSUM));
}

/* RFC 791 3.1 Time to Live: a datagram arriving with TTL 0 is destroyed;
 * TTL 1 (the boundary) is still accepted. */
static void test_xdpframe_rx_rejects_ttl_zero(void) {
  CHECK(xdpft_rejects(60, ETH_HDR + 8, 0));
  CHECK(!xdpft_rejects(60, ETH_HDR + 8, 1));
}

/* RFC 768: a non-zero UDP checksum is verified and a mismatch rejected,
 * unless the caller opts out for veth's CHECKSUM_PARTIAL frames. */
static void test_xdpframe_rx_udp_checksum(void) {
  CHECK(xdpft_rejects_f(60, 40, 0x12, 0));
  CHECK(!xdpft_rejects_f(60, 40, 0x12, XDPFRAME_SKIP_UDP_CSUM));
}

/* RFC 791 3.1 Total Length: a whole 576-octet datagram is accepted. */
static void test_xdpframe_rx_accepts_576(void) {
  static u8         buf[ETH_HDR + 576];
  static const u8   pl[576 - IPV4_HDR - UDP_HDR];
  const xdpframe_tx m = {
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x02},
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x01},
      {{4433, 5555}, {0x0a070001, 0x0a070002}},
      7};
  xdpframe_rx rx;
  usz         n = xdpframe_build(
      wired_mspan_of(buf, sizeof buf), &m, wired_span_of(pl, sizeof pl));
  CHECK(n == ETH_HDR + 576);
  CHECK(be_get_be16(buf + ETH_HDR + 2) == 576);
  CHECK(xdpframe_parse(wired_span_of(buf, n), 0, &rx) == 1);
  CHECK(rx.payload_len == sizeof pl);
}

static void test_xdpframe_rx_rejects(void) {
  CHECK(xdpft_rejects(XDPFRAME_HDRS - 1, 0, 0x02)); /* short */
  CHECK(xdpft_rejects(60, 13, 0x06));               /* ethertype ARP */
  /* IHL=6 (options present) but total length (30) is unchanged, so it no
   * longer covers the now-24-byte IP header + 8-byte UDP header (32):
   * rejected for the length mismatch, not merely for IHL != 5 (RFC 791
   * 3.1/3.2: a technically larger-but-consistent IHL is accepted --
   * test_xdpframe_rx_accepts_ihl_with_consistent_options below). */
  CHECK(xdpft_rejects(60, 14, 0x46));
  CHECK(xdpft_rejects(60, 14, 0x44)); /* IHL=4, below the RFC 791 minimum */
  CHECK(xdpft_rejects(60, 20, 0x20)); /* MF fragment bit */
  CHECK(xdpft_rejects(60, 23, 6));    /* protocol TCP */
  CHECK(xdpft_rejects(60, 39, 0x0b)); /* udp len != ip total - 20 */
  CHECK(xdpft_rejects(60, 16, 0x01)); /* ip total beyond the frame */
}

/* RFC 791 3.1/3.2: liberal in what is accepted -- an IHL larger than the
 * minimum 5 (IP options present) is not itself a reason to reject a
 * datagram whose Total Length is otherwise self-consistent; the parser
 * skips the options and finds UDP right after them. */
static const u8 xdpft_options[64] = {
    0x02, 0x07, 0x00, 0x00, 0x00, 0x01, /* eth dst (our mac) */
    0x02, 0x07, 0x00, 0x00, 0x00, 0x02, /* eth src (peer mac) */
    0x08, 0x00,                         /* ethertype IPv4 */
    0x46, 0x00, 0x00, 0x22,             /* ip: v4 IHL=6, total 34 */
    0x00, 0x00, 0x00, 0x00,             /* id, flags/frag = 0 */
    0x40, 0x11, 0x63, 0xb9,             /* ttl, proto UDP, cksum */
    10,   7,    0,    2,                /* ip src 10.7.0.2 */
    10,   7,    0,    1,                /* ip dst 10.7.0.1 */
    1,    1,    1,    1,                /* 4 bytes of IP options (NOP) */
    0x15, 0xb3, 0x11, 0x51,             /* udp sport 5555, dport 4433 */
    0x00, 0x0a, 0x00, 0x00,             /* udp len 10, cksum 0 */
    'h',  'i',                          /* payload */
    0,    0,    0,    0,    0,    0,    0, 0, 0, 0, 0, 0}; /* eth padding */

static void test_xdpframe_rx_accepts_ihl_with_consistent_options(void) {
  xdpframe_rx rx;
  CHECK(xdpframe_parse(wired_span_of(xdpft_options, 64), 0, &rx) == 1);
  CHECK(rx.dport == 4433);
  CHECK(rx.payload_len == 2 && rx.payload[0] == 'h' && rx.payload[1] == 'i');
}

/* A built frame satisfies the independent net/ verifiers and carries the
 * payload at the fixed offset; a too-small buffer is refused. */
static void test_xdpframe_tx_roundtrip(void) {
  u8                buf[128];
  const u8          pl[3] = {0xc0, 0xff, 0xee};
  const xdpframe_tx m     = {
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x02},
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x01},
      {{4433, 5555}, {0x0a070001, 0x0a070002}},
      0};
  eth_head    eh;
  xdpframe_rx rx;
  usz         n = xdpframe_build(
      wired_mspan_of(buf, sizeof(buf)), &m, wired_span_of(pl, 3));
  CHECK(n == XDPFRAME_HDRS + 3);
  CHECK(eth_parse(wired_span_of(buf, n), &eh) == 1);
  CHECK(eh.ethertype == ETH_TYPE_IPV4);
  CHECK(xdpft_mac_eq(eh.dst, m.dst_mac) && xdpft_mac_eq(eh.src, m.src_mac));
  CHECK(ipv4_check(buf + ETH_HDR) == 1);
  CHECK(
      udp4_check(
          wired_span_of(buf + ETH_HDR + IPV4_HDR, UDP_HDR + 3), m.udp.addrs) ==
      1);
  CHECK(buf[XDPFRAME_HDRS] == 0xc0 && buf[XDPFRAME_HDRS + 2] == 0xee);
  CHECK(xdpframe_parse(wired_span_of(buf, n), 0, &rx) == 1);
  CHECK(rx.dport == 5555 && rx.payload_len == 3);
  CHECK(
      xdpframe_build(
          wired_mspan_of(buf, XDPFRAME_HDRS + 2), &m, wired_span_of(pl, 3)) ==
      0);
}

/* Parsing the golden frame and reflecting its fields into a reply swaps the
 * roles exactly: the reply's peer is our old address and vice versa. */
static void test_xdpframe_reflect(void) {
  xdpframe_rx rx, rr;
  xdpframe_tx m;
  sockaddr    want_src, want_peer;
  u8          buf[64];
  const u8    pl[2] = {'y', 'o'};
  CHECK(xdpframe_parse(wired_span_of(xdpft_golden, 60), 0, &rx) == 1);
  for (usz i = 0; i < 6; i++) {
    m.dst_mac[i] = rx.peer_mac[i];
  }
  for (usz i = 0; i < 6; i++) {
    m.src_mac[i] = rx.our_mac[i];
  }
  m.udp.ports.sport = rx.dport;
  m.udp.ports.dport = xdpft_ntoh16(rx.src.port_be);
  m.udp.addrs.src   = rx.our_ip;
  m.udp.addrs.dst   = wired_udp_addr4_be(&rx.src);
  m.ip_id           = 0;
  usz n             = xdpframe_build(
      wired_mspan_of(buf, sizeof(buf)), &m, wired_span_of(pl, 2));
  CHECK(n == XDPFRAME_HDRS + 2);
  CHECK(xdpframe_parse(wired_span_of(buf, n), 0, &rr) == 1);
  wired_udp_addr(&want_src, 4433, (const u8[]){10, 7, 0, 1});
  wired_udp_addr(&want_peer, 5555, (const u8[]){10, 7, 0, 2});
  CHECK(rr.src.port_be == want_src.port_be);
  CHECK(ct_diffn(rr.src.addr, want_src.addr, 16) == 0);
  CHECK(rr.dport == 5555 && rr.our_ip == wired_udp_addr4_be(&want_peer));
  CHECK(xdpft_mac_eq(rr.peer_mac, rx.our_mac));
  CHECK(xdpft_mac_eq(rr.our_mac, rx.peer_mac));
  CHECK(rr.payload_len == 2 && rr.payload[0] == 'y');
}

void test_xdpframe(void) {
  test_xdpframe_rx_golden();
  test_xdpframe_rx_rejects();
  test_xdpframe_rx_rejects_bad_ip_checksum();
  test_xdpframe_rx_rejects_ttl_zero();
  test_xdpframe_rx_udp_checksum();
  test_xdpframe_rx_accepts_576();
  test_xdpframe_rx_accepts_ihl_with_consistent_options();
  test_xdpframe_tx_roundtrip();
  test_xdpframe_reflect();
}
