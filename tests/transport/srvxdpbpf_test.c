#include "test.h"

/* wired_srvxdpbpf drives the real bpf(2) syscall, which an unprivileged
 * test run cannot complete; each test below is green both with and without
 * CAP_BPF, checking the unwind/idempotence contracts either way. */

/* 1: close on a fresh {-1,-1,-1} object is a safe no-op, twice. */
static void test_srvxdpbpf_close_idempotent(void) {
  wired_srvxdpbpf b = {-1, -1, -1};
  wired_srvxdpbpf_close(&b);
  CHECK(b.map_fd == -1 && b.prog_fd == -1 && b.link_fd == -1);
  wired_srvxdpbpf_close(&b);
  CHECK(b.map_fd == -1 && b.prog_fd == -1 && b.link_fd == -1);
}

/* 2: register through a closed (map_fd == -1) object propagates the
 * kernel's error instead of pretending success. */
static void test_srvxdpbpf_register_bad_map(void) {
  wired_srvxdpbpf b = {-1, -1, -1};
  CHECK(wired_srvxdpbpf_register(&b, 0, 0) < 0);
}

/* 3: open on loopback (ifindex 1, generic mode) either fails cleanly —
 * without bpf(2) privileges every partially-built fd must be unwound back
 * to -1 — or, when the kernel permits it, succeeds with three live fds
 * that close() releases and resets. */
static void test_srvxdpbpf_open_paths(void) {
  wired_srvxdpbpf b;
  i64             r = wired_srvxdpbpf_open(&b, 1, 4433, 2);
  if (r < 0) {
    CHECK(b.map_fd == -1 && b.prog_fd == -1 && b.link_fd == -1);
    return;
  }
  CHECK(b.map_fd >= 0 && b.prog_fd >= 0 && b.link_fd >= 0);
  wired_srvxdpbpf_close(&b);
  CHECK(b.map_fd == -1 && b.prog_fd == -1 && b.link_fd == -1);
}

void test_srvxdpbpf(void) {
  test_srvxdpbpf_close_idempotent();
  test_srvxdpbpf_register_bad_map();
  test_srvxdpbpf_open_paths();
}
