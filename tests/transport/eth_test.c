#include "test.h"

/* Byte-range equality, local to this test. */
static int eth_bytes_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* Known MACs + EtherType 0x0800 encode to the exact 14 wire bytes. */
static void test_eth_golden(void) {
  const quic_eth_head h = {
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x01},
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x02},
      QUIC_ETH_TYPE_IPV4};
  const u8 want[QUIC_ETH_HDR] = {0x02, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02,
                                 0x07, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00};
  u8       out[QUIC_ETH_HDR];
  CHECK(quic_eth_build(out, &h) == QUIC_ETH_HDR);
  CHECK(eth_bytes_eq(out, want, QUIC_ETH_HDR));
}

/* build -> parse returns the original fields. */
static void test_eth_roundtrip(void) {
  const quic_eth_head h = {
      {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
      {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
      0x86dd};
  u8            out[QUIC_ETH_HDR];
  quic_eth_head g;
  quic_eth_build(out, &h);
  CHECK(quic_eth_parse(quic_span_of(out, QUIC_ETH_HDR), &g) == 1);
  CHECK(eth_bytes_eq(g.dst, h.dst, 6) && eth_bytes_eq(g.src, h.src, 6));
  CHECK(g.ethertype == h.ethertype);
}

/* A frame shorter than the header is rejected. */
static void test_eth_short(void) {
  u8            buf[QUIC_ETH_HDR] = {0};
  quic_eth_head g;
  CHECK(quic_eth_parse(quic_span_of(buf, QUIC_ETH_HDR - 1), &g) == 0);
}

void test_eth(void) {
  test_eth_golden();
  test_eth_roundtrip();
  test_eth_short();
}
