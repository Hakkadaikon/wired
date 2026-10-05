#define WIRED_MAIN
#include "wired.h"

/* draft-ietf-webtrans-http3-15 SS3.1 / RFC 6454: an explicit allow-list.
 * A CONNECT with no Origin header at all arrives here as an empty span --
 * the SDK itself (srvrun.c's wt_origin_ok) already answers 403 for a
 * present-but-empty Origin header before this callback ever runs, so an
 * empty span here always means "absent", never "present but empty". */
static int allowed_origin(void* ctx, wired_span origin, wired_span authority) {
  (void)ctx;
  (void)authority;
  return wired_span_eq_cstr(origin, "https://ok.example");
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-wo");
  id.max_datagram_frame_size = 65535; /* WebTransport requires DATAGRAM */

  wired_srvrun_opt opt = {0};
  opt.incoming_cpu     = -1;
  opt.wt_protocols     = "chat";
  opt.wt_origin_check  = allowed_origin;

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
