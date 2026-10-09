#define WIRED_MAIN
#include "wired.h"

#define BODY_SIZE (1024 * 1024)

/* A body bigger than body_out goes out over several rounds: each call fills
 * what fits starting at offset and sets *more until the whole body is sent.
 * Byte i of the body is (u8)i. */
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
  u64 n = BODY_SIZE - offset;
  if (n > body_out->cap) n = body_out->cap;
  for (u64 i = 0; i < n; i++) body_out->p[i] = (u8)(offset + i);
  body_out->len = n;
  *more         = offset + n < BODY_SIZE;
  *total_size   = BODY_SIZE;
  *content_type = "application/octet-stream";
  return 1;
}

int wired_main(int argc, char** argv) {
  /* Fixed demo identity (self-signed certificate; never for production). */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-h3");

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {.cb = on_request};
  wired_srvrun_obs     obs = {0};
  return wired_server_run(port, &id, h, obs) ? 0 : 1;
}
