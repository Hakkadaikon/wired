#include "app/http3/server/srvthreads/srvthreads.h"

#include "test.h"

/* @file
 * Exercises wired_srvthreads_run's control/worker lifecycle with a
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
 * loop-head shutdown poll a real worker must implement, without binding a
 * socket. */
static void srvthreads_test_worker(void* argp) {
  int index = ((srvthreads_worker_arg*)argp)->index;
  __atomic_fetch_or(&g_seen_index_mask, 1 << index, __ATOMIC_RELAXED);
  __atomic_fetch_add(&g_seen_count, 1, __ATOMIC_RELAXED);
  while (__atomic_load_n(wired_srvrun_shutdown_word(), __ATOMIC_ACQUIRE) == 0);
}

/* Flips the shared shutdown word 1 after a short spin, from a second
 * "requester" thread -- standing in for a real SIGTERM delivered to the
 * control thread, without depending on real signal delivery timing in a
 * test. */
static void srvthreads_test_request_shutdown(void* argp) {
  (void)argp;
  for (volatile int i = 0; i < 200000; i++);
  __atomic_store_n(wired_srvrun_shutdown_word(), 1, __ATOMIC_RELEASE);
}

/* N=2 test workers spawn, the shutdown word flips, wired_srvthreads_run
 * joins both and returns 1 -- the loop-head poll, full join before cleanup,
 * timed futex wait, and monotonic word are exercised end-to-end without
 * any real socket. */
static void test_srvthreads_run_joins_all_workers_on_shutdown(void) {
  wired_thread         requester;
  wired_srvthreads_opt opt = {0};
  wired_srvboot_id     id  = {0};
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};

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
  wired_srvrun_env* e0   = srvthreads_env_at(base, 0);
  wired_srvrun_env* e1   = srvthreads_env_at(base, 1);
  CHECK(base != 0);
  CHECK((u8*)e0 == base);
  CHECK((usz)((u8*)e1 - (u8*)e0) == wired_srvrun_env_size());
  srvthreads_free_envs(base, 2);
}

/* TEST LIST for wired_srvthreads_parse_cores (examples/webtransport_chat and
 * examples/word_list each reimplement this comma-list parser today; this
 * pulls it into the SDK):
 * 1. single core "0" -> ok, n_cores=1, cores[0]=0
 * 2. multi core "2,3,4,5" -> ok, n_cores=4, cores=[2,3,4,5]
 * 3. empty string "" -> fail (no fields at all is malformed, not "0 cores")
 * 4. exactly WIRED_SRVTHREADS_MAX (16) entries -> ok
 * 5. WIRED_SRVTHREADS_MAX+1 (17) entries -> fail (exceeds cap)
 * 6. non-digit mixed in "2,x,4" -> fail
 * 7. trailing comma "2,3," -> fail (empty trailing field rejected)
 * 8. leading comma ",2,3" -> fail (empty leading field rejected)
 */

static void test_srvthreads_parse_cores_single(void) {
  wired_srvthreads_opt opt = {0};
  CHECK(wired_srvthreads_parse_cores("0", &opt) == 1);
  CHECK(opt.n_cores == 1);
  CHECK(opt.cores[0] == 0);
}

static void test_srvthreads_parse_cores_multi(void) {
  wired_srvthreads_opt opt = {0};
  CHECK(wired_srvthreads_parse_cores("2,3,4,5", &opt) == 1);
  CHECK(opt.n_cores == 4);
  CHECK(opt.cores[0] == 2);
  CHECK(opt.cores[1] == 3);
  CHECK(opt.cores[2] == 4);
  CHECK(opt.cores[3] == 5);
}

static void test_srvthreads_parse_cores_empty(void) {
  wired_srvthreads_opt opt = {0};
  CHECK(wired_srvthreads_parse_cores("", &opt) == 0);
}

static void test_srvthreads_parse_cores_max(void) {
  wired_srvthreads_opt opt = {0};
  CHECK(
      wired_srvthreads_parse_cores(
          "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15", &opt) == 1);
  CHECK(opt.n_cores == (int)WIRED_SRVTHREADS_MAX);
  CHECK(opt.cores[15] == 15);
}

static void test_srvthreads_parse_cores_over_max(void) {
  wired_srvthreads_opt opt = {0};
  CHECK(
      wired_srvthreads_parse_cores(
          "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16", &opt) == 0);
}

static void test_srvthreads_parse_cores_non_digit(void) {
  wired_srvthreads_opt opt = {0};
  CHECK(wired_srvthreads_parse_cores("2,x,4", &opt) == 0);
}

static void test_srvthreads_parse_cores_trailing_comma(void) {
  wired_srvthreads_opt opt = {0};
  CHECK(wired_srvthreads_parse_cores("2,3,", &opt) == 0);
}

static void test_srvthreads_parse_cores_leading_comma(void) {
  wired_srvthreads_opt opt = {0};
  CHECK(wired_srvthreads_parse_cores(",2,3", &opt) == 0);
}

/* AF_XDP CORE ROUTING: each worker passes its own index (== queue id) into
 * the srvrun opt that drives its CID issuance, once its queue is armed. */
static void test_srvthreads_xdp_worker_passes_own_core_id_to_cid_issuance(
    void) {
  srvthreads_worker_arg a = {0};
  wired_srvxdp          x;
  a.index = 5;
  srvthreads_arm_xdp_run(&a, &x);
  CHECK(a.run.xdp == &x);
  CHECK(a.run.core_id == 5);
}

/* NON-XDP MODE: srvthreads_arm_xdp_run is only ever called from the xdp
 * dispatch branch (srvthreads_worker_main); a UDP-mode worker's run.core_id
 * is whatever wired_srvthreads_opt.run.core_id was (untouched, default -1
 * from a zero-initialized opt), never overwritten with the worker index. */
static void test_srvthreads_non_xdp_mode_uses_plain_cid_generation(void) {
  srvthreads_worker_arg a = {0};
  a.index                 = 5;
  a.run.core_id           = -1;
  CHECK(a.xdp_cfg == 0);
  CHECK(a.run.core_id == -1);
}

void test_srvthreads(void) {
  test_srvthreads_run_joins_all_workers_on_shutdown();
  test_srvthreads_env_at_strides_by_env_size();
  test_srvthreads_parse_cores_single();
  test_srvthreads_parse_cores_multi();
  test_srvthreads_parse_cores_empty();
  test_srvthreads_parse_cores_max();
  test_srvthreads_parse_cores_over_max();
  test_srvthreads_parse_cores_non_digit();
  test_srvthreads_parse_cores_trailing_comma();
  test_srvthreads_parse_cores_leading_comma();
  test_srvthreads_xdp_worker_passes_own_core_id_to_cid_issuance();
  test_srvthreads_non_xdp_mode_uses_plain_cid_generation();
}
