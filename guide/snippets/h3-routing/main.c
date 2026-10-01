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

static int reply(wired_obuf* body_out, const char** content_type, const char* text) {
  usz n = len(text);
  memcpy(body_out->p, text, n);
  body_out->len = n;
  *content_type = "text/plain";
  return 1;
}

/* Pick the response by :path. Returning 0 sends 200 with no body. */
static int on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    wired_obuf*                 body_out,
    const char**                content_type,
    int*                        more,
    u64*                        total_size) {
  (void)ctx;
  (void)offset;
  (void)more;
  (void)total_size;
  log_request(req);
  if (path_is(req, "/")) return reply(body_out, content_type, "home");
  if (path_is(req, "/about")) return reply(body_out, content_type, "about");
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
  wired_srvrun_handler h    = {on_request, 0, 0};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run(port, &id, h, obs) ? 0 : 1;
}
