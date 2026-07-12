#include "app/http3/server/srvpin/srvpin.h"

#include "common/platform/sys/syscall.h"
#include "test.h"

/* @file
 * tasks/core-pinning-plan.md test designs 1-4. sched_setaffinity/
 * sched_getaffinity are raw syscalls against the real kernel, so the test
 * verifies by issuing the same syscalls directly (no reimplementation of
 * srvpin.c).
 */

/* Raw sched_getaffinity into a 128-byte buffer (mirrors srvpin.c's own
 * WIRED_SRVPIN_MASK_BYTES), returning the syscall's result. */
static i64 sp_raw_getaffinity(u8* mask, usz n) {
  return syscall3(SYS_sched_getaffinity, 0, n, mask);
}

/* 1 iff byte i of mask has exactly bit `bit` set and every other bit (in that
 * byte) clear. */
static int sp_byte_is_only_bit(u8 byte, int bit) {
  return byte == (u8)(1 << bit);
}

/* TEST 1: on this CI environment, cpu_count returns >= 1. */
static void test_srvpin_cpu_count_at_least_one(void) {
  CHECK(wired_srvpin_cpu_count() >= 1);
}

/* TEST 2: bind_self(0) succeeds, and a raw sched_getaffinity readback shows
 * CPU 0 as the only bit set in the whole mask. */
static void test_srvpin_bind_self_zero_sets_only_cpu0(void) {
  u8 mask[128] = {0xff};
  CHECK(wired_srvpin_bind_self(0) == 0);
  CHECK(sp_raw_getaffinity(mask, sizeof mask) >= 0);
  CHECK(sp_byte_is_only_bit(mask[0], 0));
  for (usz i = 1; i < sizeof mask; i++) CHECK(mask[i] == 0);
}

/* TEST 3: an out-of-range CPU index (far beyond any real CPU count) is
 * rejected before the syscall (negative return, no kernel call needed). */
static void test_srvpin_bind_self_rejects_huge_index(void) {
  CHECK(wired_srvpin_bind_self(9999) < 0);
}

/* TEST 3b: a negative index is rejected the same way. */
static void test_srvpin_bind_self_rejects_negative_index(void) {
  CHECK(wired_srvpin_bind_self(-1) < 0);
}

/* TEST 4 (boundary contract): a CPU index that is in [0,63] (so it passes
 * srvpin's own range check) but not part of this machine's online set is left
 * to the kernel's own sched_setaffinity EINVAL -- the raw syscall's error
 * surfaces as our negative return, we do not re-validate against the online
 * set ourselves. cpu_count() is itself an upper bound on how many low
 * indices can be valid, so index 63 is a safe choice to probe this on any
 * machine with fewer than 64 CPUs; on a (hypothetical) 64-core box this
 * would legitimately succeed instead, which is why the assertion is
 * conditioned on cpu_count() first. */
static void test_srvpin_bind_self_boundary_index_63(void) {
  int cpus = wired_srvpin_cpu_count();
  int r    = wired_srvpin_bind_self(63);
  if (cpus < 64) {
    CHECK(r < 0); /* CPU 63 does not exist: kernel EINVAL surfaces */
  } else {
    CHECK(r == 0); /* CPU 63 exists on this box: legitimately succeeds */
  }
}

void test_srvpin(void) {
  test_srvpin_cpu_count_at_least_one();
  test_srvpin_bind_self_zero_sets_only_cpu0();
  test_srvpin_bind_self_rejects_huge_index();
  test_srvpin_bind_self_rejects_negative_index();
  test_srvpin_bind_self_boundary_index_63();
}
