#include "app/http3/server/sigterm/sigterm.h"
#include "test.h"

/* @file
 * wired_sigmask_block_shutdown / wired_sigmask_unblock_shutdown against the
 * real kernel: block, send ourselves a SIGTERM (survives + shows up in
 * rt_sigpending(2)), install a flag handler, unblock, and observe the pending
 * signal delivered to the handler. The install-before-unblock order is what
 * keeps SIGTERM's default action (process death) from ever firing. */

/* Linux x86_64 syscall numbers not in common/platform/sys/syscall.h. */
#define SGM_SYS_getpid 39
#define SGM_SYS_kill 62
#define SGM_SYS_rt_sigpending 127

/* rt_sigpending(2) takes sigsetsize == sizeof(u64) on this ABI. */
#define SGM_SIGSETSIZE 8

static volatile int sgm_term_hits = 0;

static void sgm_on_term(int sig) {
  (void)sig;
  sgm_term_hits++;
}

void test_sigmask(void) {
  u64 pending = 0;
  i64 pid;

  /* Block, then SIGTERM to self: we stay alive and the signal goes pending
   * (kernel sigset bit == signum - 1). */
  CHECK(wired_sigmask_block_shutdown() == 1);
  pid = syscall1(SGM_SYS_getpid, 0);
  CHECK(syscall2(SGM_SYS_kill, pid, SIGTERM) == 0);
  CHECK(syscall2(SGM_SYS_rt_sigpending, &pending, SGM_SIGSETSIZE) == 0);
  CHECK((pending & (1ull << (SIGTERM - 1))) != 0);

  /* Handler first, then unblock: the pending SIGTERM is delivered to the
   * handler (not the default action) before unblock returns. */
  CHECK(wired_sigterm_install(sgm_on_term) == 1);
  CHECK(wired_sigmask_unblock_shutdown() == 1);
  CHECK(sgm_term_hits == 1);

  /* Nothing left pending for later tests. */
  pending = 0;
  CHECK(syscall2(SGM_SYS_rt_sigpending, &pending, SGM_SIGSETSIZE) == 0);
  CHECK((pending & (1ull << (SIGTERM - 1))) == 0);
}
