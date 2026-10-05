#define WIRED_MAIN
#include "wired.h"

/* GET /stats: wired_server_wt_occupancy is a point-in-time snapshot (what is
 * open right now); wired_srvrun_env_wt_usage is the cumulative total since
 * boot. peer_streams/streams count only client-opened WT streams. */
static int on_request(void* ctx, wired_http_exchange* x) {
  wired_srvrun_env* env = (wired_srvrun_env*)ctx;
  if (!wired_span_eq_cstr(wired_h3req_path(x->req), "/stats")) {
    x->status = 404;
    return 0;
  }

  wired_wt_occupancy occ = {0};
  wired_server_wt_occupancy(&occ);
  wired_srvrun_wt_usage usage = {0};
  wired_srvrun_env_wt_usage(env, &usage);

  x->body->len = 0;
  wired_obuf_printf(
      x->body,
      "{\"occupancy\":{\"sessions\":%lu,\"sessions_cap\":%lu,"
      "\"peer_streams\":%lu,\"peer_streams_cap\":%lu},"
      "\"usage\":{\"sessions\":%lu,\"streams\":%lu,\"datagrams\":%lu}}\n",
      occ.sessions, occ.sessions_cap, occ.peer_streams, occ.peer_streams_cap,
      usage.sessions, usage.streams, usage.datagrams);
  x->content_type = "application/json";
  return 1;
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-st");

  /* wired_srvrun_env_wt_usage needs an addressable env, unlike the single
   * process-wide instance wired_server_run/wired_server_run_opt drive --
   * same one-instance mmap srvthreads.c uses for its per-worker envs. */
  i64 envsz = (i64)wired_srvrun_env_size();
  i64 base  = wired_arch_mmap(
      0, envsz, 0x3 /* PROT_READ|PROT_WRITE */,
      0x22 /* MAP_PRIVATE|MAP_ANONYMOUS */, -1, 0);
  if (base < 0) return 1;
  wired_srvrun_env* env = (wired_srvrun_env*)base;
  wired_srvrun_env_init(env);

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {.http = on_request, .ctx = env};
  wired_srvrun_obs     obs = {0};
  wired_srvrun_opt     opt = {0};
  opt.incoming_cpu         = -1;
  return wired_srvrun_serve_env(env, port, &id, h, obs, &opt) ? 0 : 1;
}
