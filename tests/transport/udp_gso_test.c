#include "test.h"

/* wired_udp_gso_cmsg_build's whole output: cmsg_len=18 (u64 LE), cmsg_level=
 * SOL_UDP(17)/cmsg_type=UDP_SEGMENT(103) (i32 LE each), segsize=1200 (u16 LE),
 * zero-padded to WIRED_GSO_CMSG_SPACE (24, Linux CMSG_SPACE rounding). One
 * golden comparison proves the whole layout; the kernel-facing round-trip
 * (test_send_gso_delivers_total_bytes below) proves it is accepted for real. */
static void test_gso_cmsg_build(void) {
  static const u8 want[WIRED_GSO_CMSG_SPACE] = {
      18,  0, 0, 0, 0, 0, 0, 0, /* cmsg_len */
      17,  0, 0, 0,             /* cmsg_level = SOL_UDP */
      103, 0, 0, 0,             /* cmsg_type = UDP_SEGMENT */
      176, 4,                   /* segsize = 1200 (LE) */
      0,   0, 0, 0, 0, 0,       /* padding to CMSG_SPACE */
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
static int gso_open_sockets(i64* sfd, i64* cfd, quic_sockaddr* srv) {
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
  i64           sfd, cfd;
  quic_sockaddr srv;
  u8            payload[30]; /* 3 segments of 10 bytes */
  for (usz i = 0; i < sizeof payload; i++) payload[i] = (u8)i;
  if (!gso_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  CHECK(
      wired_udp_send_batch(
          cfd, &srv, quic_span_of(payload, sizeof payload), 10) ==
      (i64)sizeof payload);
  CHECK(gso_recv_count(sfd) == 3);
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* wired_udp_send_gso (real UDP_SEGMENT path) delivers the same total bytes
 * across >=1 datagram(s) on a kernel that supports UDP_SEGMENT (>= 4.18). */
static void test_send_gso_delivers_total_bytes(void) {
  i64           sfd, cfd;
  quic_sockaddr srv;
  u8            payload[30];
  for (usz i = 0; i < sizeof payload; i++) payload[i] = (u8)i;
  if (!gso_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  wired_udp_gso_enable(cfd, 10);
  CHECK(
      wired_udp_send_gso(
          cfd, &srv, quic_span_of(payload, sizeof payload), 10) ==
      (i64)sizeof payload);
  CHECK(gso_recv_count(sfd) == 3);
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* wired_udp_reuseport_enable, set on two sockets BEFORE bind, lets both bind
 * the same fixed port (4437, distinct from the GSO tests' 4436) — without
 * SO_REUSEPORT the second bind would fail with EADDRINUSE. Benign skip when
 * the sandbox forbids sockets, same pattern as gso_open_sockets above. */
static void test_reuseport_enable_allows_shared_bind(void) {
  i64           fd1, fd2;
  quic_sockaddr addr;
  fd1 = wired_udp_socket();
  if (fd1 < 0) return; /* sandbox: skip */
  fd2 = wired_udp_socket();
  if (fd2 < 0) {
    wired_udp_close(fd1);
    return; /* sandbox: skip */
  }
  wired_udp_addr(&addr, 4437, (const u8[4]){127, 0, 0, 1});
  if (wired_udp_reuseport_enable(fd1) < 0 ||
      wired_udp_reuseport_enable(fd2) < 0) {
    wired_udp_close(fd1);
    wired_udp_close(fd2);
    return; /* sandbox: skip (SO_REUSEPORT unsupported) */
  }
  if (wired_udp_bind(fd1, &addr) < 0) {
    wired_udp_close(fd1);
    wired_udp_close(fd2);
    return; /* sandbox: skip */
  }
  CHECK(wired_udp_bind(fd2, &addr) == 0);
  wired_udp_close(fd1);
  wired_udp_close(fd2);
}

/* wired_udp_recvmmsg_nowait on a socket with nothing queued returns
 * immediately (negative errno), never blocks. */
static void test_recvmmsg_nowait_returns_immediately_when_empty(void) {
  i64           sfd, cfd;
  quic_sockaddr srv;
  u8            rx[64];
  quic_mmsg_buf bufs[1] = {{quic_mspan_of(rx, sizeof rx), {0}, 0, 0}};
  if (!gso_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  CHECK(wired_udp_recvmmsg_nowait(sfd, bufs, 1) < 0);
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* wired_udp_recvmmsg_nowait after a real send delivers the datagram, same as
 * the blocking wired_udp_recvmmsg would once data is queued. */
static void test_recvmmsg_nowait_delivers_queued_datagram(void) {
  i64           sfd, cfd;
  quic_sockaddr srv;
  u8            rx[64];
  quic_mmsg_buf bufs[1]    = {{quic_mspan_of(rx, sizeof rx), {0}, 0, 0}};
  const u8      payload[5] = {1, 2, 3, 4, 5};
  if (!gso_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  CHECK(
      wired_udp_send(cfd, &srv, quic_span_of(payload, sizeof payload)) ==
      (i64)sizeof payload);
  CHECK(wired_udp_recvmmsg_nowait(sfd, bufs, 1) == 1);
  CHECK(bufs[0].len == sizeof payload);
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* wired_udp_busy_poll_enable on a real socket returns without crashing
 * whether or not the kernel/driver actually supports SO_BUSY_POLL. */
static void test_busy_poll_enable_does_not_crash(void) {
  i64 fd = wired_udp_socket();
  if (fd < 0) return; /* sandbox: skip */
  wired_udp_busy_poll_enable(fd, 50);
  wired_udp_close(fd);
  CHECK(1);
}

/* Same testability bar as test_busy_poll_enable_does_not_crash above (tasks/
 * polling-driver-plan.md POLL-003b): call the real setsockopt on a real
 * socket, confirm it does not crash. Not verifying kernel-side effect. */
static void test_prefer_busy_poll_enable_does_not_crash(void) {
  i64 fd = wired_udp_socket();
  if (fd < 0) return; /* sandbox: skip */
  wired_udp_prefer_busy_poll_enable(fd, 1);
  wired_udp_close(fd);
  CHECK(1);
}

static void test_busy_poll_budget_set_does_not_crash(void) {
  i64 fd = wired_udp_socket();
  if (fd < 0) return; /* sandbox: skip */
  wired_udp_busy_poll_budget_set(fd, 8);
  wired_udp_close(fd);
  CHECK(1);
}

/* tasks/core-pinning-plan.md PIN-007, SET direction only. */
static void test_incoming_cpu_set_does_not_crash(void) {
  i64 fd = wired_udp_socket();
  if (fd < 0) return; /* sandbox: skip */
  wired_udp_incoming_cpu_set(fd, 0);
  wired_udp_close(fd);
  CHECK(1);
}

/* Same as gso_open_sockets but on a distinct port (4438) and with IP_RECVTOS
 * enabled on the server socket, so ECN tests do not collide with the fixed-
 * port 4436/4437 socket pairs above. */
static int ecn_open_sockets(i64* sfd, i64* cfd, quic_sockaddr* srv) {
  *sfd = wired_udp_socket();
  if (*sfd < 0) return 0;
  wired_udp_addr(srv, 4438, (const u8[4]){127, 0, 0, 1});
  if (wired_udp_bind(*sfd, srv) < 0) {
    wired_udp_close(*sfd);
    return 0;
  }
  wired_udp_recvtos_enable(*sfd);
  *cfd = wired_udp_socket();
  if (*cfd < 0) {
    wired_udp_close(*sfd);
    return 0;
  }
  return 1;
}

/* T-001: wired_udp_ect0_enable on the sending socket marks every packet it
 * sends ECT(0) (RFC 9000 13.4.1) -- observed on the receiving end via
 * IP_RECVTOS + wired_udp_recvmmsg's cmsg read (T-002's path), since this SDK
 * has no getsockopt to read IP_TOS back directly. */
static void test_udp_ect0_enable_sets_tos(void) {
  i64           sfd, cfd;
  quic_sockaddr srv;
  u8            rx[64];
  quic_mmsg_buf bufs[1]    = {{quic_mspan_of(rx, sizeof rx), {0}, 0, 0}};
  const u8      payload[3] = {1, 2, 3};
  if (!ecn_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  CHECK(wired_udp_ect0_enable(cfd) == 0);
  CHECK(
      wired_udp_send(cfd, &srv, quic_span_of(payload, sizeof payload)) ==
      (i64)sizeof payload);
  CHECK(wired_udp_recvmmsg(sfd, bufs, 1) == 1);
  CHECK(bufs[0].ecn == 2); /* ECT(0) */
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* T-005: a sender that never called wired_udp_ect0_enable delivers Not-ECT
 * (0) -- no cmsg is attached for an unmarked packet, and cmsg_read_ip_tos's
 * absent-cmsg fallback must not fabricate a nonzero ECN reading. */
static void test_udp_recvmmsg_no_cmsg_defaults_to_zero_e2e(void) {
  i64           sfd, cfd;
  quic_sockaddr srv;
  u8            rx[64];
  quic_mmsg_buf bufs[1]    = {{quic_mspan_of(rx, sizeof rx), {0}, 0, 0}};
  const u8      payload[3] = {9, 9, 9};
  if (!ecn_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  CHECK(
      wired_udp_send(cfd, &srv, quic_span_of(payload, sizeof payload)) ==
      (i64)sizeof payload);
  CHECK(wired_udp_recvmmsg(sfd, bufs, 1) == 1);
  CHECK(bufs[0].ecn == 0);
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* T-004: a batch of 3 ECT(0)-marked datagrams in one recvmmsg() call reads
 * ECN bits into each slot individually (no cross-slot bleed from a shared
 * cmsg scratch buffer). */
static void test_udp_recvmmsg_batch_ecn_per_slot(void) {
  i64           sfd, cfd;
  quic_sockaddr srv;
  u8            rx0[64], rx1[64], rx2[64];
  quic_mmsg_buf bufs[3] = {
      {quic_mspan_of(rx0, sizeof rx0), {0}, 0, 0},
      {quic_mspan_of(rx1, sizeof rx1), {0}, 0, 0},
      {quic_mspan_of(rx2, sizeof rx2), {0}, 0, 0}};
  const u8 payload[3] = {1, 2, 3};
  int      n, i;
  if (!ecn_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  CHECK(wired_udp_ect0_enable(cfd) == 0);
  for (i = 0; i < 3; i++)
    CHECK(
        wired_udp_send(cfd, &srv, quic_span_of(payload, sizeof payload)) ==
        (i64)sizeof payload);
  n = (int)wired_udp_recvmmsg(sfd, bufs, 3);
  CHECK(n == 3);
  for (i = 0; i < n; i++) CHECK(bufs[i].ecn == 2); /* ECT(0), every slot */
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* T-018: a setsockopt failure (invalid fd) propagates its negative errno
 * unchanged, rather than being swallowed -- no fallback path is implemented
 * (see wired_udp_ect0_enable's doc for why that is out of scope here). */
static void test_udp_ect0_enable_propagates_setsockopt_failure(void) {
  CHECK(wired_udp_ect0_enable(-1) < 0);
  CHECK(wired_udp_recvtos_enable(-1) < 0);
}

void test_udp_gso(void) {
  test_gso_cmsg_build();
  test_send_batch_delivers_segments();
  test_send_gso_delivers_total_bytes();
  test_reuseport_enable_allows_shared_bind();
  test_recvmmsg_nowait_returns_immediately_when_empty();
  test_recvmmsg_nowait_delivers_queued_datagram();
  test_busy_poll_enable_does_not_crash();
  test_prefer_busy_poll_enable_does_not_crash();
  test_busy_poll_budget_set_does_not_crash();
  test_incoming_cpu_set_does_not_crash();
  test_udp_ect0_enable_sets_tos();
  test_udp_recvmmsg_no_cmsg_defaults_to_zero_e2e();
  test_udp_recvmmsg_batch_ecn_per_slot();
  test_udp_ect0_enable_propagates_setsockopt_failure();
}
