#include "app/http3/server/srvdriver/srvdriver.h"

#include "app/http3/server/srvpin/srvpin.h"
#include "common/platform/cliargs/cliargs.h"
#include "common/platform/exit/exit.h"

/* --workers cannot combine with --cores/--ifindex (a different SDK entry
 * point entirely); --ifindex alone still composes with --cores (AF_XDP
 * multi-queue mode, see srvdriver_load_threads). */
static int srvdriver_conflict(int has_workers, int has_xdp, int has_cores) {
  if (!has_workers) return 0;
  return has_xdp || has_cores;
}

/* Which driver to run once has_workers is known not to conflict. */
static wired_srvdriver_kind srvdriver_select_tail(
    int has_workers, int has_xdp) {
  if (has_xdp) return WIRED_SRVDRIVER_XDP;
  if (has_workers) return WIRED_SRVDRIVER_WORKERS;
  return WIRED_SRVDRIVER_PLAIN;
}

static wired_srvdriver_kind srvdriver_select(
    int has_workers, int has_xdp, int has_cores) {
  if (has_cores) return WIRED_SRVDRIVER_THREADS;
  return srvdriver_select_tail(has_workers, has_xdp);
}

/* XDP_FLAGS_SKB_MODE (2) when --skb-mode is set, else native mode (0). */
static u32 srvdriver_xdp_attach_flags(int argc, char** argv) {
  if (wired_cliargs_flag(argc, argv, "--skb-mode")) return 2u;
  return 0u;
}

/* --ifindex/--ip/--queue/--skb-mode into opt->xdp (opt->port, already
 * resolved by wired_srvdriver_parse, seeds the BPF redirect filter). Shared
 * by WIRED_SRVDRIVER_XDP and WIRED_SRVDRIVER_THREADS (the latter when
 * --ifindex was also given, selecting AF_XDP multi-queue mode: worker i
 * serves queue i). */
static int srvdriver_load_xdp(int argc, char** argv, wired_srvdriver_opt* opt) {
  wired_srvxdp_cfg* xdp     = &opt->xdp;
  i64               ifindex = wired_cliargs_int(argc, argv, "--ifindex", -1);
  if (ifindex < 0) return 0;
  if (!wired_cliargs_ipv4(wired_cliargs_str(argc, argv, "--ip", ""), xdp->ip))
    return 0;
  xdp->ifindex      = (u32)ifindex;
  xdp->queue_id     = (u32)wired_cliargs_int(argc, argv, "--queue", 0);
  xdp->port         = opt->port;
  xdp->bind_flags   = 0;
  xdp->attach_flags = srvdriver_xdp_attach_flags(argc, argv);
  return 1;
}

static int srvdriver_load_workers(
    int argc, char** argv, wired_srvworkers_opt* w) {
  w->workers   = (int)wired_cliargs_int(argc, argv, "--workers", 0);
  w->pin_cores = (int)wired_cliargs_int(argc, argv, "--pin-cores", 0);
  return 1;
}

/* threads.cores/n_cores/control_core/run, independent of --ifindex. */
static int srvdriver_load_threads_cores(
    int argc, char** argv, wired_srvthreads_opt* threads) {
  const char* cores_str = wired_cliargs_str(argc, argv, "--cores", "");
  if (!wired_srvthreads_parse_cores(cores_str, threads)) return 0;
  threads->control_core =
      (int)wired_cliargs_int(argc, argv, "--control-core", -1);
  threads->run              = (wired_srvrun_opt){0};
  threads->run.incoming_cpu = -1;
  return 1;
}

/* threads.xdp: 0 unless --ifindex selects AF_XDP multi-queue mode, in which
 * case opt->xdp is filled and threads.xdp points at it. */
static int srvdriver_load_threads_xdp(
    int argc, char** argv, wired_srvdriver_opt* opt) {
  if (wired_cliargs_int(argc, argv, "--ifindex", -1) < 0) {
    opt->threads.xdp = 0;
    return 1;
  }
  if (!srvdriver_load_xdp(argc, argv, opt)) return 0;
  opt->threads.xdp = &opt->xdp;
  return 1;
}

/* --cores/--control-core into opt->threads; when --ifindex is also present,
 * fills opt->xdp too and points threads.xdp at it (AF_XDP multi-queue). */
static int srvdriver_load_threads(
    int argc, char** argv, wired_srvdriver_opt* opt) {
  if (!srvdriver_load_threads_cores(argc, argv, &opt->threads)) return 0;
  return srvdriver_load_threads_xdp(argc, argv, opt);
}

/* kind has its own pinning knob (--pin-cores for WORKERS, --control-core for
 * THREADS) that --pin-core would conflict with. */
static int srvdriver_kind_has_own_pinning(wired_srvdriver_kind kind) {
  return kind == WIRED_SRVDRIVER_WORKERS || kind == WIRED_SRVDRIVER_THREADS;
}

/* opt->pin_core / --pin-core's exclusivity with WORKERS/THREADS. */
static int srvdriver_load_pin_core(
    int argc, char** argv, wired_srvdriver_kind kind, int* pin_core) {
  *pin_core = (int)wired_cliargs_int(argc, argv, "--pin-core", -1);
  if (*pin_core < 0) return 1;
  return !srvdriver_kind_has_own_pinning(kind);
}

/* Uniform-signature wrappers, one per kind, so srvdriver_load_kind can
 * dispatch through a table instead of an if/if/if chain (CCN). */
static int srvdriver_load_kind_plain(
    int argc, char** argv, wired_srvdriver_opt* opt) {
  (void)argc;
  (void)argv;
  (void)opt;
  return 1;
}

static int srvdriver_load_kind_workers(
    int argc, char** argv, wired_srvdriver_opt* opt) {
  return srvdriver_load_workers(argc, argv, &opt->workers);
}

static int srvdriver_load_kind_xdp(
    int argc, char** argv, wired_srvdriver_opt* opt) {
  return srvdriver_load_xdp(argc, argv, opt);
}

typedef int (*srvdriver_load_fn)(int, char**, wired_srvdriver_opt*);

static const srvdriver_load_fn SRVDRIVER_LOAD_BY_KIND[4] = {
    srvdriver_load_kind_plain,   /* WIRED_SRVDRIVER_PLAIN */
    srvdriver_load_kind_workers, /* WIRED_SRVDRIVER_WORKERS */
    srvdriver_load_kind_xdp,     /* WIRED_SRVDRIVER_XDP */
    srvdriver_load_threads,      /* WIRED_SRVDRIVER_THREADS */
};

/* Loads the knobs for the already-selected driver; a no-op for PLAIN beyond
 * --pin-core (srvdriver_load_pin_core, called separately by the caller). */
static int srvdriver_load_kind(
    int argc, char** argv, wired_srvdriver_opt* opt) {
  return SRVDRIVER_LOAD_BY_KIND[opt->kind](argc, argv, opt);
}

/* opt is zeroed and its port/kind/pin_core resolved up front (all trivially
 * revertible on failure), then filled in place by srvdriver_load_kind --
 * NOT via a local wired_srvdriver_opt copied in at the end, since
 * srvdriver_load_threads points opt->threads.xdp at opt->xdp itself; copying
 * a self-referential struct by value would leave that pointer dangling at
 * the copy's own address instead of the caller's. */
int wired_srvdriver_parse(int argc, char** argv, wired_srvdriver_opt* opt) {
  int has_workers = wired_cliargs_int(argc, argv, "--workers", -1) >= 0;
  int has_xdp     = wired_cliargs_int(argc, argv, "--ifindex", -1) >= 0;
  int has_cores   = wired_cliargs_str(argc, argv, "--cores", 0) != 0;
  if (srvdriver_conflict(has_workers, has_xdp, has_cores)) return 0;
  *opt      = (wired_srvdriver_opt){0};
  opt->port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  opt->kind = srvdriver_select(has_workers, has_xdp, has_cores);
  if (!srvdriver_load_pin_core(argc, argv, opt->kind, &opt->pin_core)) return 0;
  return srvdriver_load_kind(argc, argv, opt);
}

static int srvdriver_run_plain(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt) {
  if (opt->pin_core >= 0 && wired_srvpin_bind_self(opt->pin_core) < 0)
    wired_die("--pin-core: pinning failed (bad CPU index?)\n");
  return wired_server_run_opt(opt->port, id, h, obs, &opt->run);
}

static int srvdriver_run_workers(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt) {
  wired_srvrun_obs wobs = {0, 0, obs.cert_path, obs.key_path, obs.cc_algo};
  return wired_srvworkers_run(opt->port, id, h, wobs, &opt->workers) >= 0;
}

static int srvdriver_run_xdp(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt) {
  wired_srvxdp     xdp = {0};
  wired_srvrun_opt run;
  int              ok;
  if (wired_srvxdp_open(&xdp, &opt->xdp) < 0) wired_die("AF_XDP open failed\n");
  run     = opt->run;
  run.xdp = &xdp;
  ok      = wired_server_run_opt(opt->port, id, h, obs, &run);
  wired_srvxdp_print_stats(xdp.xsk.fd);
  wired_srvxdp_close(&xdp);
  return ok;
}

static int srvdriver_run_threads(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt) {
  return wired_srvthreads_run(opt->port, id, h, obs, &opt->threads);
}

typedef int (*srvdriver_run_fn)(
    wired_srvboot_id*,
    wired_srvrun_handler,
    wired_srvrun_obs,
    const wired_srvdriver_opt*);

static const srvdriver_run_fn SRVDRIVER_RUN_BY_KIND[4] = {
    srvdriver_run_plain,   /* WIRED_SRVDRIVER_PLAIN */
    srvdriver_run_workers, /* WIRED_SRVDRIVER_WORKERS */
    srvdriver_run_xdp,     /* WIRED_SRVDRIVER_XDP */
    srvdriver_run_threads, /* WIRED_SRVDRIVER_THREADS */
};

int wired_srvdriver_run(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt) {
  return SRVDRIVER_RUN_BY_KIND[opt->kind](id, h, obs, opt);
}
