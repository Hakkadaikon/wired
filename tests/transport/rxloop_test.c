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

  const u8* pkts[4];
  usz       offs[4], lens[4];
  pktlist   out = {pkts, offs, lens, 4};
  usz       got = udploop_split(wired_span_of(dg, n), &out);

  CHECK(got == 2);
  CHECK(offs[0] == 0 && lens[0] == initial_len && pkts[0] == dg);
  CHECK(offs[1] == initial_len && lens[1] == 4 && pkts[1] == dg + initial_len);
}

/* A single short-header packet yields one packet spanning the datagram. */
static void test_rx_split_one(void) {
  u8        dg[4] = {0x40, 1, 2, 3};
  const u8* pkts[2];
  usz       offs[2], lens[2];
  pktlist   out = {pkts, offs, lens, 2};
  usz       got = udploop_split(wired_span_of(dg, 4), &out);
  CHECK(got == 1 && offs[0] == 0 && lens[0] == 4);
}

/* An empty datagram yields no packets (mirrors an EAGAIN recv of zero). */
static void test_rx_split_empty(void) {
  const u8* pkts[2];
  usz       offs[2], lens[2];
  pktlist   out = {pkts, offs, lens, 2};
  CHECK(udploop_split(wired_span_of((const u8*)0, 0), &out) == 0);
}

/* max_pkts caps how many packets are recorded. */
static void test_rx_split_cap(void) {
  u8        dg[4] = {0x40, 1, 2, 3};
  const u8* pkts[1];
  usz       offs[1], lens[1];
  pktlist   out = {pkts, offs, lens, 0};
  CHECK(udploop_split(wired_span_of(dg, 4), &out) == 0);
}

/* GHSA-hxq4-mx37-fqvg class (s2n-quic, V-0490): a legitimate zero-length
 * UDP datagram must not crash or be mistaken for coalesced packet data.
 * Real loopback send/recv (socket() may be sandbox-denied -- benign skip,
 * same convention as udp_test.c's test_udp_socket_dualstack). */
static void test_udploop_rx_zero_length_datagram_no_crash(void) {
  i64 fd = wired_udp_socket();
  if (fd < 0) return;
  sockaddr loop;
  wired_udp_addr(&loop, 0, (const u8[4]){127, 0, 0, 1});
  if (wired_udp_bind(fd, &loop) < 0) {
    wired_udp_close(fd);
    return;
  }
  sockaddr bound;
  u64      addrlen = sizeof(bound);
  if (syscall3(51 /* getsockname */, fd, (i64)&bound, (i64)&addrlen) < 0) {
    wired_udp_close(fd);
    return;
  }
  CHECK(wired_udp_send(fd, &bound, wired_span_of((const u8*)"", 0)) == 0);

  u8        buf[64];
  const u8* pkts[4];
  usz       offs[4], lens[4];
  pktlist   out = {pkts, offs, lens, 4};
  usz       got = udploop_rx(fd, wired_mspan_of(buf, sizeof buf), &out);
  CHECK(got == 0); /* no packet handed to frame/coalesce parsing */
  wired_udp_close(fd);
}

void test_rxloop(void) {
  test_rx_split_two();
  test_rx_split_one();
  test_rx_split_empty();
  test_rx_split_cap();
  test_udploop_rx_zero_length_datagram_no_crash();
}
