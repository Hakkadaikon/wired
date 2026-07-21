#include "app/http3/server/srvdriver/srvdriver.h"

#include "test.h"

/* @file
 * wired_srvdriver_parse tests only -- wired_srvdriver_run drives a real
 * server loop per selected driver (wired_server_run_opt / wired_srvworkers_
 * run / wired_srvthreads_run), already covered by each driver's own
 * integration tests; re-testing the dispatch itself would need the same
 * real-socket harness those already have, so it is left to the examples
 * that consume this API end-to-end.
 *
 * Test list (t-wada style, boundary values / equivalence classes):
 * - no flags -> PLAIN (the default), opt.port == 4433
 * - --port N -> opt.port == N, on every driver kind
 * - --workers N -> WORKERS, opt.workers.workers == N
 * - --cores a,b -> THREADS, opt.threads.n_cores == 2
 * - --ifindex N (no --cores) -> XDP, opt.xdp.port == opt.port (regression:
 *   the BPF redirect filter must key off the SAME port wired_srvdriver_run
 *   binds/serves on, not a re-derived --port with a different default)
 * - --workers + --cores -> conflict, returns 0
 * - --workers + --ifindex -> conflict, returns 0
 * - --pin-core + --workers -> conflict, returns 0
 * - --pin-core + --cores -> conflict, returns 0
 * - --pin-core alone (PLAIN) -> success, opt.pin_core set
 * - --cores malformed (e.g. "x") -> returns 0 (wired_srvthreads_parse_cores
 *   itself rejects it)
 */

static void test_srvdriver_parse_default_is_plain(void) {
  char*               argv[] = {"prog"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(1, argv, &opt) == 1);
  CHECK(opt.kind == WIRED_SRVDRIVER_PLAIN);
  CHECK(opt.port == 4433);
}

static void test_srvdriver_parse_port(void) {
  char*               argv[] = {"prog", "--port", "8443"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(3, argv, &opt) == 1);
  CHECK(opt.port == 8443);
}

static void test_srvdriver_parse_workers(void) {
  char*               argv[] = {"prog", "--workers", "4"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(3, argv, &opt) == 1);
  CHECK(opt.kind == WIRED_SRVDRIVER_WORKERS);
  CHECK(opt.workers.workers == 4);
}

static void test_srvdriver_parse_threads(void) {
  char*               argv[] = {"prog", "--cores", "2,3"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(3, argv, &opt) == 1);
  CHECK(opt.kind == WIRED_SRVDRIVER_THREADS);
  CHECK(opt.threads.n_cores == 2);
  CHECK(opt.threads.cores[0] == 2);
  CHECK(opt.threads.cores[1] == 3);
  CHECK(opt.threads.xdp == 0);
}

/* Regression test: the XDP driver's BPF redirect filter is built from
 * opt->xdp.port, which must end up equal to opt->port (the same value
 * wired_srvdriver_run binds/serves on) -- a real bug this test now catches:
 * --port absent, wired_srvdriver_run's own default 4433, but this function's
 * now-removed separate --port re-parse defaulted to 0, so the filter
 * silently matched port 0 and dropped every real packet before it ever
 * reached the QUIC stack. */
static void test_srvdriver_parse_xdp(void) {
  char*               argv[] = {"prog", "--ifindex", "3", "--ip", "10.0.0.1"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(5, argv, &opt) == 1);
  CHECK(opt.kind == WIRED_SRVDRIVER_XDP);
  CHECK(opt.xdp.ifindex == 3);
  CHECK(opt.xdp.port == opt.port);
  CHECK(opt.xdp.port == 4433);
}

static void test_srvdriver_parse_threads_with_xdp(void) {
  char*               argv[] = {"prog", "--cores", "0,1",     "--ifindex",
                                "2",    "--ip",    "10.0.0.1"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(7, argv, &opt) == 1);
  CHECK(opt.kind == WIRED_SRVDRIVER_THREADS);
  CHECK(opt.threads.xdp == &opt.xdp);
  CHECK(opt.xdp.ifindex == 2);
  CHECK(opt.xdp.port == opt.port);
}

static void test_srvdriver_parse_workers_cores_conflict(void) {
  char*               argv[] = {"prog", "--workers", "2", "--cores", "0,1"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(5, argv, &opt) == 0);
}

static void test_srvdriver_parse_workers_ifindex_conflict(void) {
  char*               argv[] = {"prog", "--workers", "2", "--ifindex", "0"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(5, argv, &opt) == 0);
}

static void test_srvdriver_parse_pin_core_workers_conflict(void) {
  char*               argv[] = {"prog", "--pin-core", "1", "--workers", "2"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(5, argv, &opt) == 0);
}

static void test_srvdriver_parse_pin_core_cores_conflict(void) {
  char*               argv[] = {"prog", "--pin-core", "1", "--cores", "0,1"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(5, argv, &opt) == 0);
}

static void test_srvdriver_parse_pin_core_alone(void) {
  char*               argv[] = {"prog", "--pin-core", "2"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(3, argv, &opt) == 1);
  CHECK(opt.kind == WIRED_SRVDRIVER_PLAIN);
  CHECK(opt.pin_core == 2);
}

static void test_srvdriver_parse_cores_malformed(void) {
  char*               argv[] = {"prog", "--cores", "x"};
  wired_srvdriver_opt opt    = {0};
  CHECK(wired_srvdriver_parse(3, argv, &opt) == 0);
}

/* App-facing run options set on opt.run AFTER wired_srvdriver_parse (the
 * documented pattern every example uses: parse, then opt.run.wt_on_datagram
 * = cb) must reach the worker threads of the --cores driver. They did not:
 * the threads loader rebuilt its own run from zero at parse time, so a
 * WebTransport chat server run with --cores silently dropped every received
 * datagram (callback 0 = deliver-nowhere consume). */
static wired_wt_on_datagram g_sd_seen_dg_cb;
static void*                g_sd_seen_dg_ctx;

static void sd_marker_dg_cb(void* ctx, wired_wt_session* s, quic_span d) {
  (void)ctx;
  (void)s;
  (void)d;
}

static void sd_run_recorder_worker(void* argp) {
  srvthreads_worker_arg* a = (srvthreads_worker_arg*)argp;
  g_sd_seen_dg_cb          = a->run.wt_on_datagram;
  g_sd_seen_dg_ctx         = a->run.wt_datagram_ctx;
  while (__atomic_load_n(wired_srvrun_shutdown_word(), __ATOMIC_ACQUIRE) == 0);
}

static void sd_request_shutdown(void* argp) {
  (void)argp;
  for (volatile int i = 0; i < 200000; i++);
  __atomic_store_n(wired_srvrun_shutdown_word(), 1, __ATOMIC_RELEASE);
}

static void test_srvdriver_threads_propagates_run_opts(void) {
  char*                argv[] = {"prog", "--cores", "0", "--port", "14461"};
  wired_srvdriver_opt  opt    = {0};
  wired_srvboot_id     id     = {0};
  wired_srvrun_handler h      = {0};
  wired_srvrun_obs     obs    = {0};
  wired_thread         requester;
  int                  ctx_probe;

  CHECK(wired_srvdriver_parse(5, argv, &opt) == 1);
  opt.run.wt_on_datagram  = sd_marker_dg_cb;
  opt.run.wt_datagram_ctx = &ctx_probe;

  __atomic_store_n(wired_srvrun_shutdown_word(), 0, __ATOMIC_RELEASE);
  g_sd_seen_dg_cb  = 0;
  g_sd_seen_dg_ctx = 0;
  srvthreads_test_set_worker_fn(sd_run_recorder_worker);
  wired_thread_start(&requester, sd_request_shutdown, 0);

  CHECK(wired_srvdriver_run(&id, h, obs, &opt) == 1);

  wired_thread_join(&requester);
  srvthreads_test_set_worker_fn(0);
  __atomic_store_n(wired_srvrun_shutdown_word(), 0, __ATOMIC_RELEASE);

  CHECK(g_sd_seen_dg_cb == sd_marker_dg_cb);
  CHECK(g_sd_seen_dg_ctx == &ctx_probe);
}

void test_srvdriver(void) {
  test_srvdriver_parse_default_is_plain();
  test_srvdriver_parse_port();
  test_srvdriver_parse_workers();
  test_srvdriver_parse_threads();
  test_srvdriver_parse_xdp();
  test_srvdriver_parse_threads_with_xdp();
  test_srvdriver_parse_workers_cores_conflict();
  test_srvdriver_parse_workers_ifindex_conflict();
  test_srvdriver_parse_pin_core_workers_conflict();
  test_srvdriver_parse_pin_core_cores_conflict();
  test_srvdriver_parse_pin_core_alone();
  test_srvdriver_parse_cores_malformed();
  test_srvdriver_threads_propagates_run_opts();
}
