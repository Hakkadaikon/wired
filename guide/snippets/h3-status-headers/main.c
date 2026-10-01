#define WIRED_MAIN
#include "wired.h"

static usz len(const char* s) {
  usz n = 0;
  while (s[n]) n++;
  return n;
}

static int span_is(wired_span s, const char* lit) {
  usz n = len(lit);
  if (s.n != n) return 0;
  for (usz i = 0; i < n; i++)
    if (s.p[i] != (u8)lit[i]) return 0;
  return 1;
}

static int path_is(const wired_h3reqdrive_req* req, const char* p) {
  return span_is(wired_span_of(req->path, req->path_len), p);
}

static void set_header(
    wired_http_field* f, const char* name, const char* value) {
  *f = (wired_http_field){
      wired_span_of((const u8*)name, len(name)),
      wired_span_of((const u8*)value, len(value))};
}

static int reply(wired_http_exchange* x, u16 status, const char* body) {
  usz n = len(body);
  x->status       = status;
  x->content_type = "text/plain";
  memcpy(x->body->p, body, n);
  x->body->len = n;
  return 1;
}

/* 1 if the request carries either the Bearer token or the session cookie
 * a prior /login round would have handed out. */
static int authorized(const wired_h3reqdrive_req* req) {
  wired_span v;
  if (wired_http_req_header(
          req, wired_span_of((const u8*)"authorization", 13), &v) &&
      span_is(v, "Bearer secret-token"))
    return 1;
  return req->cookie_len > 0 &&
         span_is(wired_span_of(req->cookie, req->cookie_len), "session=granted");
}

/* Three routes, one wired_http_handler each demonstrates: a 3xx with
 * Location, a Set-Cookie, and an authorization check reading either the
 * Authorization header or the cookie set by /login. */
static int on_request(void* ctx, wired_http_exchange* x) {
  (void)ctx;
  if (path_is(x->req, "/redirect")) {
    x->status = 302;
    set_header(&x->fields[0], "location", "/target");
    x->field_count = 1;
    return 0;
  }
  if (path_is(x->req, "/login")) {
    set_header(&x->fields[0], "set-cookie", "session=granted");
    x->field_count = 1;
    return reply(x, 200, "logged in");
  }
  if (path_is(x->req, "/secret"))
    return authorized(x->req) ? reply(x, 200, "top secret")
                               : reply(x, 403, "forbidden");
  return reply(x, 404, "not found");
}

int wired_main(int argc, char** argv) {
  /* A fixed demo identity: X25519 key share, certificate signing seed,
   * connection id and ServerHello.random. The certificate is self-signed. */
  static u8       priv[32], pub[32], seed[32], rnd[32];
  static const u8 scid[] = "guide-h3";
  wired_srvboot_id id = {0};
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x50 + i);
    seed[i] = (u8)(0x90 + i);
    rnd[i]  = (u8)(0xb0 + i);
  }
  wired_x25519_base(pub, priv);
  id.priv      = priv;
  id.pub       = pub;
  id.cert_seed = seed;
  id.random    = rnd;
  id.scid      = scid;
  id.scid_len  = sizeof scid - 1; /* without the string's NUL */

  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h    = {0, 0, on_request};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run(port, &id, h, obs) ? 0 : 1;
}
