#define WIRED_MAIN
#include "wired.h"

static void set_header(
    wired_http_field* f, const char* name, const char* value) {
  *f = (wired_http_field){wired_span_cstr(name), wired_span_cstr(value)};
}

static int reply(wired_http_exchange* x, u16 status, const char* body) {
  x->status       = status;
  x->content_type = "text/plain";
  wired_obuf_printf(x->body, "%s", body);
  return 1;
}

/* 1 if the request carries either the Bearer token or the session cookie
 * a prior /login round would have handed out. */
static int authorized(const wired_h3reqdrive_req* req) {
  wired_span v;
  if (wired_http_req_header(req, wired_span_cstr("authorization"), &v) &&
      wired_span_eq_cstr(v, "Bearer secret-token"))
    return 1;
  return wired_span_eq_cstr(
      wired_span_of(req->cookie, req->cookie_len), "session=granted");
}

/* Three routes, one wired_http_handler each demonstrates: a 3xx with
 * Location, a Set-Cookie, and an authorization check reading either the
 * Authorization header or the cookie set by /login. */
static int on_request(void* ctx, wired_http_exchange* x) {
  (void)ctx;
  wired_span path = wired_h3req_path(x->req);
  if (wired_span_eq_cstr(path, "/redirect")) {
    x->status = 302;
    set_header(&x->fields[0], "location", "/target");
    x->field_count = 1;
    return 0;
  }
  if (wired_span_eq_cstr(path, "/login")) {
    set_header(&x->fields[0], "set-cookie", "session=granted");
    x->field_count = 1;
    return reply(x, 200, "logged in");
  }
  if (wired_span_eq_cstr(path, "/secret"))
    return authorized(x->req) ? reply(x, 200, "top secret")
                              : reply(x, 401, "unauthorized");
  return reply(x, 404, "not found");
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
