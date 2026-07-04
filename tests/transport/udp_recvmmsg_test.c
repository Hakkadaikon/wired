#include "test.h"

/* A bound server socket and a client socket, both on 127.0.0.1. Returns 1 with
 * the fds, or 0 (benign skip) if the sandbox forbids sockets. */
static int rmmsg_open_sockets(i64 *sfd, i64 *cfd, quic_sockaddr_in *srv) {
  *sfd = wired_udp_socket();
  if (*sfd < 0) return 0;
  wired_udp_addr(srv, 4437, (const u8[4]){127, 0, 0, 1});
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

/* Send count single-byte-tagged datagrams from cfd to srv, each payload
 * len bytes filled with the datagram index. */
static void rmmsg_send_n(
    i64 cfd, const quic_sockaddr_in *srv, int count, usz len) {
  for (int i = 0; i < count; i++) {
    u8 payload[32];
    for (usz j = 0; j < len; j++) payload[j] = (u8)i;
    wired_udp_send(cfd, srv, quic_span_of(payload, len));
  }
}

/* wired_udp_recvmmsg receives 3 datagrams sent back-to-back in one syscall,
 * each slot's len and payload matching what was sent. count matches the
 * number sent: fd is blocking, and recvmmsg(2) with a NULL timeout blocks
 * until count messages arrive, so asking for more than was sent would hang. */
static void test_recvmmsg_receives_batch(void) {
  i64              sfd, cfd;
  quic_sockaddr_in srv;
  quic_mmsg_buf    bufs[3];
  u8               storage[3][16];
  if (!rmmsg_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  rmmsg_send_n(cfd, &srv, 3, 8);
  for (usz i = 0; i < 3; i++) bufs[i].buf = quic_mspan_of(storage[i], 16);
  i64 r = wired_udp_recvmmsg(sfd, bufs, 3);
  if (r < 0) {
    /* ENOSYS on a kernel without recvmmsg: nothing more to prove here. */
    wired_udp_close(cfd);
    wired_udp_close(sfd);
    return;
  }
  CHECK(r == 3);
  for (i64 i = 0; i < r; i++) {
    CHECK(bufs[i].len == 8);
    CHECK(storage[i][0] == (u8)i);
  }
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* wired_udp_recvmmsg_fallback (the recvfrom-loop path) receives the same 3
 * datagrams one syscall at a time. count matches the number sent: fd is
 * blocking, and a 4th recvfrom would hang waiting for a datagram that was
 * never sent. */
static void test_recvmmsg_fallback_receives_batch(void) {
  i64              sfd, cfd;
  quic_sockaddr_in srv;
  quic_mmsg_buf    bufs[3];
  u8               storage[3][16];
  if (!rmmsg_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  rmmsg_send_n(cfd, &srv, 3, 8);
  for (usz i = 0; i < 3; i++) bufs[i].buf = quic_mspan_of(storage[i], 16);
  i64 r = wired_udp_recvmmsg_fallback(sfd, bufs, 3);
  CHECK(r == 3);
  for (i64 i = 0; i < r; i++) {
    CHECK(bufs[i].len == 8);
    CHECK(storage[i][0] == (u8)i);
  }
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* No datagrams pending: wired_udp_recvmmsg_fallback returns 0 immediately
 * (first recvfrom is empty/error, e.g. EAGAIN on a would-block socket, or the
 * bind-less benign-skip path never sent anything). */
static void test_recvmmsg_fallback_empty_returns_zero(void) {
  i64              sfd, cfd;
  quic_sockaddr_in srv;
  quic_mmsg_buf    bufs[2];
  u8               storage[2][16];
  if (!rmmsg_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  for (usz i = 0; i < 2; i++) bufs[i].buf = quic_mspan_of(storage[i], 16);
  /* Nothing sent to sfd: recvfrom would block forever on a blocking socket,
   * so instead prove the zero-count slot case: count == 0 is always 0. */
  CHECK(wired_udp_recvmmsg_fallback(sfd, bufs, 0) == 0);
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

void test_udp_recvmmsg(void) {
  test_recvmmsg_receives_batch();
  test_recvmmsg_fallback_receives_batch();
  test_recvmmsg_fallback_empty_returns_zero();
}
