#define WIRED_MAIN
#include "wired.h"

/* A browser (or any WebTransport client) opened a session on `path`. */
static void on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  (void)ctx;
  (void)s;
  (void)protocol;
  wired_dprintf(2, "session %.*s\n", WIRED_SPAN_ARG(path));
}

/* Echo every datagram back to the session it came from. */
static void on_datagram(void* ctx, wired_wt_session* s, wired_span data) {
  (void)ctx;
  wired_server_wt_send_datagram_to(s, data);
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-wt");
  id.max_datagram_frame_size = 65535; /* WebTransport requires DATAGRAM */

  wired_srvrun_opt opt = {0};
  opt.incoming_cpu     = -1;
  opt.wt_on_session    = on_session;
  opt.wt_on_datagram   = on_datagram;

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
