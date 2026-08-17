#include "transport/io/xdp/xsksetup/xsksetup.h"

#include "test.h"

/* AF_XDP socket creation/bind needs CAP_NET_RAW-equivalent privilege this
 * sandbox normally lacks, so xsksetup_open() is expected to fail with a
 * negative errno here -- same "sandbox: skip" convention as
 * tests/app/srvpoll_test.c and tests/transport/xdpbpf_test.c. When it DOES
 * succeed (e.g. run as root), every ring must be fully wired up. */
static void test_xsksetup_open_close(void) {
  xsk     x;
  xsk_cfg cfg = {1, 0, 2 /* XDP_COPY */};
  i64     r   = xsksetup_open(&x, &cfg);
  if (r < 0) return; /* sandbox: skip */
  CHECK(x.umem != 0);
  CHECK(x.rx.producer != 0 && x.rx.consumer != 0);
  CHECK(x.tx.producer != 0 && x.tx.consumer != 0);
  CHECK(x.fill.producer != 0 && x.fill.consumer != 0);
  CHECK(x.comp.producer != 0 && x.comp.consumer != 0);
  xsksetup_close(&x);
}

/* A bad ifindex (0 is never valid) must fail cleanly: no crash, negative
 * return, and xsksetup_close on the (unopened) result must still be
 * safe (double-close style). */
static void test_xsksetup_open_rejects_bad_ifindex(void) {
  xsk     x;
  xsk_cfg cfg = {0, 0, 2};
  i64     r   = xsksetup_open(&x, &cfg);
  CHECK(r < 0);
  xsksetup_close(&x);
}

/* xsksetup_kick_tx must never crash regardless of fd validity; an
 * invalid fd yields a negative errno rather than a signal. */
static void test_xsksetup_kick_tx_survives_bad_fd(void) {
  i64 r = xsksetup_kick_tx(-1);
  CHECK(r < 0);
}

/* xsksetup_stats must never crash on an invalid fd either. */
static void test_xsksetup_stats_survives_bad_fd(void) {
  u64 stats[6] = {0};
  i64 r        = xsksetup_stats(-1, stats);
  CHECK(r < 0);
}

void test_xsksetup(void) {
  test_xsksetup_open_close();
  test_xsksetup_open_rejects_bad_ifindex();
  test_xsksetup_kick_tx_survives_bad_fd();
  test_xsksetup_stats_survives_bad_fd();
}
