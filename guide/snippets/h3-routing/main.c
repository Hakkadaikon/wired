#define WIRED_MAIN
#include "wired.h"

static usz len(const char* s) {
  usz n = 0;
  while (s[n]) n++;
  return n;
}

static int path_is(const wired_h3reqdrive_req* req, const char* path) {
  usz n = len(path);
  if (req->path_len != n) return 0;
  for (usz i = 0; i < n; i++)
    if (req->path[i] != (u8)path[i]) return 0;
  return 1;
}

static void log_request(const wired_h3reqdrive_req* req) {
  char line[128] = "request ";
  usz  n         = req->path_len < 100 ? req->path_len : 100;
  memcpy(line + 8, req->path, n);
  line[8 + n]     = '\n';
  line[8 + n + 1] = 0;
  wired_log_str(line);
}

static int reply(wired_http_exchange* x, const char* text) {
  usz n = len(text);
  memcpy(x->body->p, text, n);
  x->body->len   = n;
  x->content_type = "text/plain";
  return 1;
}

/* Pick the response by :path; an unknown path answers a real 404
 * (wired_http_handler can choose the status, unlike the 7-argument
 * handler, which always sends 200). */
static int on_request(void* ctx, wired_http_exchange* x) {
  (void)ctx;
  log_request(x->req);
  if (path_is(x->req, "/")) return reply(x, "home");
  if (path_is(x->req, "/about")) return reply(x, "about");
  x->status = 404;
  return 0;
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
  wired_srvrun_handler h    = {0, 0, on_request, 0};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run(port, &id, h, obs) ? 0 : 1;
}
