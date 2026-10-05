#define WIRED_MAIN
#include "wired.h"

/* Decide per :path, before the session exists. Leaving `out` untouched
 * accepts; a non-zero status is sent instead of 200. */
static void on_resource(
    void*                       ctx,
    wired_span                  authority,
    wired_span                  path,
    wired_wt_resource_decision* out) {
  (void)ctx;
  (void)authority;
  if (wired_span_eq_cstr(path, "/forbidden")) out->status = 405;
}

static void on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  (void)ctx;
  (void)s;
  wired_dprintf(2, "session %.*s\n", WIRED_SPAN_ARG(path));
  wired_dprintf(2, "protocol %.*s\n", WIRED_SPAN_ARG(protocol));
}

/* Fires once per session, however it ended. Release per-session state here. */
static void on_session_close(void* ctx, wired_wt_session* s) {
  (void)ctx;
  (void)s;
  wired_log_str("session closed\n");
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-wt");
  id.max_datagram_frame_size = 65535; /* WebTransport requires DATAGRAM */

  wired_srvrun_opt opt    = {0};
  opt.incoming_cpu        = -1;
  opt.wt_resource_check   = on_resource;
  opt.wt_protocols        = "chat"; /* space-separated list we accept */
  opt.wt_on_session       = on_session;
  opt.wt_on_session_close = on_session_close;

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
