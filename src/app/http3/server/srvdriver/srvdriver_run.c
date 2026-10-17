#include "app/http3/server/srvdriver/srvdriver_impl.h"

static int srvdriver_run_plain(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt);
static int srvdriver_run_workers(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt);
static int srvdriver_run_xdp(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt);

int wired_srvdriver_parse(int argc, char** argv, wired_srvdriver_opt* opt) {
  if (!srvdriver_parse_head(argc, argv, opt)) return 0;
  if (!srvdriver_load_kind(argc, argv, opt)) return 0;
  opt->run.force_retry = wired_cliargs_flag(argc, argv, "--force-retry");
  return 1;
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

/* opt->run copied at run time, same rule as srvdriver_run_threads/_xdp. */
static int srvdriver_run_workers(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt) {
  wired_srvrun_obs     wobs = {0, 0, obs.cert_path, obs.key_path, obs.cc_algo};
  wired_srvworkers_opt w    = opt->workers;
  w.run                     = opt->run;
  return wired_srvworkers_run(opt->port, id, h, wobs, &w) >= 0;
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

/* opt->run is copied in at RUN time, not parse time (same rule as
 * srvdriver_run_xdp's `run = opt->run`): every example sets its app-facing
 * run options (wt_on_datagram etc.) on opt.run AFTER wired_srvdriver_parse,
 * and a parse-time copy would hand every worker a stale zeroed run -- a
 * --cores chat server dropped every received datagram exactly this way. */
int srvdriver_run_threads(
    wired_srvboot_id*          id,
    wired_srvrun_handler       h,
    wired_srvrun_obs           obs,
    const wired_srvdriver_opt* opt) {
  wired_srvthreads_opt t = opt->threads;
  t.run                  = opt->run;
  return wired_srvthreads_run(opt->port, id, h, obs, &t);
}

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
