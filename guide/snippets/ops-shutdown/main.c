#define WIRED_MAIN
#include "wired.h"

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
  (void)more;
  (void)total_size;
  *content_type = "text/plain";
  wired_obuf_printf(body_out, "ok");
  return 1;
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-h3");

  /* --port, --workers, --cores, --ifindex, ... pick and configure a driver. */
  wired_srvdriver_opt opt = {0};
  if (!wired_srvdriver_parse(argc, argv, &opt)) {
    wired_log_str("bad flags\n");
    return 2;
  }
  wired_srvrun_handler h   = {.cb = on_request};
  wired_srvrun_obs     obs = {0};
  return wired_srvdriver_run(&id, h, obs, &opt) < 0 ? 1 : 0;
}
