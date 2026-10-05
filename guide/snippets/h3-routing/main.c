#define WIRED_MAIN
#include "wired.h"

static int reply(wired_http_exchange* x, const char* text) {
  wired_obuf_printf(x->body, "%s", text);
  x->content_type = "text/plain";
  return 1;
}

/* Pick the response by :path; an unknown path answers a real 404
 * (wired_http_handler can choose the status, unlike the 7-argument
 * handler, which always sends 200). */
static int on_request(void* ctx, wired_http_exchange* x) {
  (void)ctx;
  wired_span path = wired_h3req_path(x->req);
  wired_dprintf(2, "request %.*s\n", WIRED_SPAN_ARG(path));
  if (wired_span_eq_cstr(path, "/")) return reply(x, "home");
  if (wired_span_eq_cstr(path, "/about")) return reply(x, "about");
  x->status = 404;
  return 0;
}

int wired_main(int argc, char** argv) {
  /* A fixed demo identity: X25519 key share, certificate signing seed,
   * connection id and ServerHello.random. The certificate is self-signed. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-h3");

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {.http = on_request};
  wired_srvrun_obs     obs = {0};
  return wired_server_run(port, &id, h, obs) ? 0 : 1;
}
