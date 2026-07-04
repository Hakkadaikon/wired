#include "test.h"

/* wired_udp_gso_cmsg_build's whole output: cmsg_len=18 (u64 LE), cmsg_level=
 * SOL_UDP(17)/cmsg_type=UDP_SEGMENT(103) (i32 LE each), segsize=1200 (u16 LE),
 * zero-padded to WIRED_GSO_CMSG_SPACE (24, Linux CMSG_SPACE rounding). One
 * golden comparison proves the whole layout; the kernel-facing round-trip
 * (test_send_gso_delivers_total_bytes below) proves it is accepted for real. */
static void test_gso_cmsg_build(void) {
  static const u8 want[WIRED_GSO_CMSG_SPACE] = {
      18, 0, 0, 0, 0, 0, 0, 0, /* cmsg_len */
      17, 0, 0, 0,             /* cmsg_level = SOL_UDP */
      103, 0, 0, 0,            /* cmsg_type = UDP_SEGMENT */
      176, 4,                  /* segsize = 1200 (LE) */
      0, 0, 0, 0, 0, 0,        /* padding to CMSG_SPACE */
  };
  u8  buf[WIRED_GSO_CMSG_SPACE];
  int eq = 1;
  wired_udp_gso_cmsg_build(buf, 1200);
  for (usz i = 0; i < WIRED_GSO_CMSG_SPACE; i++)
    if (buf[i] != want[i]) eq = 0;
  CHECK(eq);
}

/* A bound server socket and a client socket, both on 127.0.0.1. Returns 1 with
 * the fds, or 0 (benign skip) if the sandbox forbids sockets. */
static int gso_open_sockets(i64 *sfd, i64 *cfd, quic_sockaddr_in *srv) {
  *sfd = wired_udp_socket();
  if (*sfd < 0) return 0;
  wired_udp_addr(srv, 4436, (const u8[4]){127, 0, 0, 1});
  if (wired_udp_bind(*sfd, srv) < 0) {
    wired_udp_close(*sfd);
    return 0;
  }
  *cfd = wired_udp_socket();
  if (*cfd < 0) {
    wired_udp_close(*sfd);
    return 0;
  }
  return 1;
}

/* Receive up to 3 datagrams on sfd, counting how many actually arrived. */
static int gso_recv_count(i64 sfd) {
  u8  rx[64];
  int n = 0;
  for (int i = 0; i < 3; i++) {
    if (wired_udp_recv(sfd, quic_mspan_of(rx, sizeof rx)) <= 0) break;
    n++;
  }
  return n;
}

/* wired_udp_send_batch (the always-available fallback path) delivers each
 * segment as its own datagram: 3 segments in, 3 datagrams received. */
static void test_send_batch_delivers_segments(void) {
  i64              sfd, cfd;
  quic_sockaddr_in srv;
  u8               payload[30]; /* 3 segments of 10 bytes */
  for (usz i = 0; i < sizeof payload; i++) payload[i] = (u8)i;
  if (!gso_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  CHECK(
      wired_udp_send_batch(cfd, &srv, quic_span_of(payload, sizeof payload), 10) ==
      (i64)sizeof payload);
  CHECK(gso_recv_count(sfd) == 3);
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* wired_udp_send_gso (real UDP_SEGMENT path) delivers the same total bytes
 * across >=1 datagram(s) on a kernel that supports UDP_SEGMENT (>= 4.18). */
static void test_send_gso_delivers_total_bytes(void) {
  i64              sfd, cfd;
  quic_sockaddr_in srv;
  u8               payload[30];
  for (usz i = 0; i < sizeof payload; i++) payload[i] = (u8)i;
  if (!gso_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  wired_udp_gso_enable(cfd, 10);
  CHECK(
      wired_udp_send_gso(cfd, &srv, quic_span_of(payload, sizeof payload), 10) ==
      (i64)sizeof payload);
  CHECK(gso_recv_count(sfd) == 3);
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

void test_udp_gso(void) {
  test_gso_cmsg_build();
  test_send_batch_delivers_segments();
  test_send_gso_delivers_total_bytes();
}
