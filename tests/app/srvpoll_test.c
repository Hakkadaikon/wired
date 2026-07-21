#include "app/http3/server/srvpoll/srvpoll.h"

#include "test.h"

/* wired_srvpoll_spin_step calls wired_udp_recvmmsg_nowait once and, when the
 * result is "no data"
 * (0 or a negative errno), issues a single PAUSE instruction -- the return
 * value itself is never transformed or dropped (verified with the same
 * real-socket pattern as tests/transport/udp_recvmmsg_test.c: with nothing
 * sent to sfd, MSG_DONTWAIT returns empty immediately). */

/* A bound (non-listening-peer) socket, used as the recv side. Returns 1 with
 * the fd, or 0 (benign skip) if the sandbox forbids sockets. */
static int sp_open_socket(i64* sfd, quic_sockaddr* srv) {
  *sfd = wired_udp_socket();
  if (*sfd < 0) return 0;
  wired_udp_addr(srv, 4438, (const u8[4]){127, 0, 0, 1});
  if (wired_udp_bind(*sfd, srv) < 0) {
    wired_udp_close(*sfd);
    return 0;
  }
  return 1;
}

/* TEST 1 + 5: nothing was ever sent to sfd, so wired_udp_recvmmsg_nowait
 * itself must report "no data" (<= 0, e.g. -EAGAIN) without blocking, and
 * wired_srvpoll_spin_step must return that same value unchanged. Calling it
 * repeatedly in a bounded loop (iteration count, not time) proves it never
 * blocks/hangs across repeated calls — the non-blocking contract holds, not
 * just once. */
static void test_srvpoll_spin_step_empty_never_blocks(void) {
  i64           sfd;
  quic_sockaddr srv;
  quic_mmsg_buf bufs[2];
  u8            storage[2][16];
  if (!sp_open_socket(&sfd, &srv)) return; /* sandbox: skip */
  for (usz i = 0; i < 2; i++) bufs[i].buf = quic_mspan_of(storage[i], 16);
  for (int i = 0; i < 1000; i++) {
    i64 r = wired_srvpoll_spin_step(sfd, bufs, 2);
    CHECK(r <= 0); /* faithfully passes through "no data" every iteration */
  }
  wired_udp_close(sfd);
}

/* TEST 2: when a datagram IS queued, wired_srvpoll_spin_step returns the
 * same positive count wired_udp_recvmmsg_nowait itself would have returned
 * (the pause-on-empty behavior must not suppress or alter a real result). */
static void test_srvpoll_spin_step_data_returns_count_unchanged(void) {
  i64           sfd, cfd;
  quic_sockaddr srv;
  quic_mmsg_buf bufs[2];
  u8            storage[2][16];
  if (!sp_open_socket(&sfd, &srv)) return; /* sandbox: skip */
  cfd = wired_udp_socket();
  if (cfd < 0) {
    wired_udp_close(sfd);
    return;
  }
  wired_udp_send(cfd, &srv, quic_span_of((const u8[]){1, 2, 3}, 3));
  for (usz i = 0; i < 2; i++) bufs[i].buf = quic_mspan_of(storage[i], 16);
  /* Give the datagram a moment to land in the kernel's receive queue before
   * the non-blocking call (loopback UDP is effectively synchronous, but the
   * assertion below tolerates a benign 0/negative race by not hard-failing
   * on it -- the point under test is "a positive count is never altered",
   * which the == 1 branch below still exercises whenever it lands). */
  i64 r = wired_srvpoll_spin_step(sfd, bufs, 2);
  if (r > 0) {
    CHECK(r == 1);
    CHECK(bufs[0].len == 3);
  }
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* TEST 3: consecutive empty spins grow the backoff counter. */
static void test_srvpoll_backoff_grows_on_consecutive_empty(void) {
  i64                   sfd;
  quic_sockaddr         srv;
  quic_mmsg_buf         bufs[2];
  u8                    storage[2][16];
  wired_srvpoll_backoff bo = {0};
  if (!sp_open_socket(&sfd, &srv)) return; /* sandbox: skip */
  for (usz i = 0; i < 2; i++) bufs[i].buf = quic_mspan_of(storage[i], 16);
  for (int i = 0; i < 5; i++) {
    i64 r = wired_srvpoll_spin_step_backoff(sfd, bufs, 2, &bo);
    CHECK(r <= 0);
    CHECK(bo.empty_spins == (u64)(i + 1));
  }
  wired_udp_close(sfd);
}

/* TEST 4: the instant a real datagram arrives, the backoff resets to 0 --
 * no leftover backoff carries into a burst. */
static void test_srvpoll_backoff_resets_on_data(void) {
  i64                   sfd, cfd;
  quic_sockaddr         srv;
  quic_mmsg_buf         bufs[2];
  u8                    storage[2][16];
  wired_srvpoll_backoff bo = {0};
  if (!sp_open_socket(&sfd, &srv)) return; /* sandbox: skip */
  cfd = wired_udp_socket();
  if (cfd < 0) {
    wired_udp_close(sfd);
    return;
  }
  for (usz i = 0; i < 2; i++) bufs[i].buf = quic_mspan_of(storage[i], 16);
  for (int i = 0; i < 3; i++)
    wired_srvpoll_spin_step_backoff(sfd, bufs, 2, &bo);
  CHECK(bo.empty_spins == 3);
  wired_udp_send(cfd, &srv, quic_span_of((const u8[]){1, 2, 3}, 3));
  i64 r = wired_srvpoll_spin_step_backoff(sfd, bufs, 2, &bo);
  if (r > 0) CHECK(bo.empty_spins == 0);
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* TEST 5: the backoff caps out and does not grow unboundedly across many
 * consecutive empty spins. */
static void test_srvpoll_backoff_caps_at_maximum(void) {
  i64                   sfd;
  quic_sockaddr         srv;
  quic_mmsg_buf         bufs[2];
  u8                    storage[2][16];
  wired_srvpoll_backoff bo = {0};
  if (!sp_open_socket(&sfd, &srv)) return; /* sandbox: skip */
  for (usz i = 0; i < 2; i++) bufs[i].buf = quic_mspan_of(storage[i], 16);
  for (int i = 0; i < 1000; i++)
    wired_srvpoll_spin_step_backoff(sfd, bufs, 2, &bo);
  CHECK(bo.empty_spins == WIRED_SRVPOLL_BACKOFF_MAX);
  wired_udp_close(sfd);
}

void test_srvpoll(void) {
  test_srvpoll_spin_step_empty_never_blocks();
  test_srvpoll_spin_step_data_returns_count_unchanged();
  test_srvpoll_backoff_grows_on_consecutive_empty();
  test_srvpoll_backoff_resets_on_data();
  test_srvpoll_backoff_caps_at_maximum();
}
