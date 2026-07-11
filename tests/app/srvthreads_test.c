#include "app/http3/server/srvthreads/srvthreads.h"

#include "test.h"

/* @file
 * Phase D lifecycle tests (tasks/loopeng/srvthreads-lifecycle/summary.md):
 * exercise wired_srvthreads_run's control/worker lifecycle with a
 * substituted worker body (srvthreads_test_set_worker_fn, same seam as
 * srvworkers_test.c's g_srvworkers_child_fn) so no real socket/AF_XDP queue
 * is ever opened and the run is bounded -- a test worker just observes the
 * shared shutdown word and returns once it is set. */

/** How many test workers actually ran (indexes 0..n-1 all touched it,
 * proving all N threads were spawned and dispatched through the hook). */
static int g_seen_index_mask;
static int g_seen_count;

/* Test worker body: record which index this thread was given (the unity
 * build includes srvthreads.c ahead of this file, so srvthreads_worker_arg
 * is directly visible here, no lookalike struct needed), then spin on the
 * shared shutdown word (same word wired_srvthreads_run's control thread
 * waits on) until it reads non-zero, and return -- exercising the same
 * "loop-head shutdown poll" contract summary.md requires of a real worker,
 * without binding a socket. */
static void srvthreads_test_worker(void* argp) {
  int index = ((srvthreads_worker_arg*)argp)->index;
  __atomic_fetch_or(&g_seen_index_mask, 1 << index, __ATOMIC_RELAXED);
  __atomic_fetch_add(&g_seen_count, 1, __ATOMIC_RELAXED);
  while (__atomic_load_n(wired_srvrun_shutdown_word(), __ATOMIC_ACQUIRE) == 0)
    ;
}

/* Flips the shared shutdown word 1 after a short spin, from a second
 * "requester" thread -- standing in for a real SIGTERM delivered to the
 * control thread, without depending on real signal delivery timing in a
 * test. */
static void srvthreads_test_request_shutdown(void* argp) {
  (void)argp;
  for (volatile int i = 0; i < 200000; i++)
    ;
  __atomic_store_n(wired_srvrun_shutdown_word(), 1, __ATOMIC_RELEASE);
}

/* TEST: N=2 test workers spawn, the shutdown word flips, wired_srvthreads_run
 * joins both and returns 1 -- constraints 1/3/5/6 (loop-head poll, full
 * join before cleanup, timed futex wait, monotonic word) exercised
 * end-to-end without any real socket. */
static void test_srvthreads_run_joins_all_workers_on_shutdown(void) {
  wired_thread          requester;
  wired_srvthreads_opt  opt = {0};
  wired_srvboot_id      id  = {0};
  wired_srvrun_handler  h   = {0};
  wired_srvrun_obs      obs = {0};

  __atomic_store_n(wired_srvrun_shutdown_word(), 0, __ATOMIC_RELEASE);
  g_seen_index_mask = 0;
  g_seen_count      = 0;

  opt.n_cores      = 2;
  opt.control_core = -1;
  opt.cores[0]     = 0;
  opt.cores[1]     = 1;

  srvthreads_test_set_worker_fn(srvthreads_test_worker);
  wired_thread_start(&requester, srvthreads_test_request_shutdown, 0);

  CHECK(wired_srvthreads_run(4433, &id, h, obs, &opt) == 1);

  wired_thread_join(&requester);
  CHECK(g_seen_count == 2);
  CHECK(g_seen_index_mask == 0x3); /* both index 0 and index 1 dispatched */
  CHECK(__atomic_load_n(wired_srvrun_shutdown_word(), __ATOMIC_ACQUIRE) == 1);

  srvthreads_test_set_worker_fn(0);
  __atomic_store_n(wired_srvrun_shutdown_word(), 0, __ATOMIC_RELEASE);
}

/* TEST: srvthreads_alloc_envs reserves exactly n_cores * env_size() bytes --
 * proven indirectly via srvthreads_env_at's stride (each worker's env
 * pointer is base + i*env_size(), and the two pointers used by a real N=2
 * run above are exactly one env_size() apart). */
static void test_srvthreads_env_at_strides_by_env_size(void) {
  u8*               base = srvthreads_alloc_envs(2);
  wired_srvrun_env* e0    = srvthreads_env_at(base, 0);
  wired_srvrun_env* e1    = srvthreads_env_at(base, 1);
  CHECK(base != 0);
  CHECK((u8*)e0 == base);
  CHECK((usz)((u8*)e1 - (u8*)e0) == wired_srvrun_env_size());
  srvthreads_free_envs(base, 2);
}

void test_srvthreads(void) {
  test_srvthreads_run_joins_all_workers_on_shutdown();
  test_srvthreads_env_at_strides_by_env_size();
}
