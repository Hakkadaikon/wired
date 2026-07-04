#include "test.h"

/* RFC 9000 12.2: split a received datagram of two coalesced packets into
 * their offsets and lengths. */
static void test_rx_split_two(void) {
  u8  dg[32];
  usz n           = 0;
  dg[n++]         = 0xC0; /* Initial long header */
  dg[n++]         = 0;
  dg[n++]         = 0;
  dg[n++]         = 0;
  dg[n++]         = 1;
  dg[n++]         = 0;
  dg[n++]         = 0;
  dg[n++]         = 0; /* DCID/SCID/token lens */
  dg[n++]         = 3; /* Length 3 */
  dg[n++]         = 0xAA;
  dg[n++]         = 0xBB;
  dg[n++]         = 0xCC; /* payload */
  usz initial_len = n;
  dg[n++]         = 0x40;
  dg[n++]         = 1;
  dg[n++]         = 2;
  dg[n++]         = 3; /* short to end */

  const u8*    pkts[4];
  usz          offs[4], lens[4];
  quic_pktlist out = {pkts, offs, lens, 4};
  usz          got = quic_udploop_split(quic_span_of(dg, n), &out);

  CHECK(got == 2);
  CHECK(offs[0] == 0 && lens[0] == initial_len && pkts[0] == dg);
  CHECK(offs[1] == initial_len && lens[1] == 4 && pkts[1] == dg + initial_len);
}

/* A single short-header packet yields one packet spanning the datagram. */
static void test_rx_split_one(void) {
  u8           dg[4] = {0x40, 1, 2, 3};
  const u8*    pkts[2];
  usz          offs[2], lens[2];
  quic_pktlist out = {pkts, offs, lens, 2};
  usz          got = quic_udploop_split(quic_span_of(dg, 4), &out);
  CHECK(got == 1 && offs[0] == 0 && lens[0] == 4);
}

/* An empty datagram yields no packets (mirrors an EAGAIN recv of zero). */
static void test_rx_split_empty(void) {
  const u8*    pkts[2];
  usz          offs[2], lens[2];
  quic_pktlist out = {pkts, offs, lens, 2};
  CHECK(quic_udploop_split(quic_span_of((const u8*)0, 0), &out) == 0);
}

/* max_pkts caps how many packets are recorded. */
static void test_rx_split_cap(void) {
  u8           dg[4] = {0x40, 1, 2, 3};
  const u8*    pkts[1];
  usz          offs[1], lens[1];
  quic_pktlist out = {pkts, offs, lens, 0};
  CHECK(quic_udploop_split(quic_span_of(dg, 4), &out) == 0);
}

void test_rxloop(void) {
  test_rx_split_two();
  test_rx_split_one();
  test_rx_split_empty();
  test_rx_split_cap();
}
