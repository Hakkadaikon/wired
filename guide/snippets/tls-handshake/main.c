#define WIRED_MAIN
#include "wired.h"

/* No HTTP traffic is expected: the client only completes the handshake. */
static int on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    wired_obuf*                 body_out,
    const char**                content_type,
    int*                        more,
    u64*                        total_size) {
  (void)ctx;
  (void)req;
  (void)offset;
  (void)body_out;
  (void)content_type;
  (void)more;
  (void)total_size;
  return 0;
}

int wired_main(int argc, char** argv) {
  /* Fixed demo identity (self-signed certificate; never for production). */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-tl");

  /* --port and the driver flags (--workers, --cores, ...) come from argv. */
  wired_srvdriver_opt opt;
  if (!wired_srvdriver_parse(argc, argv, &opt)) return 1;
  wired_srvrun_handler h   = {.cb = on_request};
  wired_srvrun_obs     obs = {0};
  return wired_srvdriver_run(&id, h, obs, &opt) ? 0 : 1;
}
