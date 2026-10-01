#define WIRED_MAIN
#include "wired.h"

/* The whole point of this page: wired_staticfile_resolve rejects path
 * traversal and picks an index file for a directory request, then
 * wired_mimetype_for_path infers the Content-Type from the resolved
 * file's extension. */

static int not_found(wired_http_exchange* x) {
  static const u8 body[] = "not found";
  x->status       = 404;
  x->content_type = "text/plain";
  memcpy(x->body->p, body, sizeof body - 1);
  x->body->len = sizeof body - 1;
  return 1;
}

/* NUL-terminate req->path (truncated to cap-1 bytes) into reqpath. */
static void reqpath_copy(
    char* reqpath, usz cap, const wired_h3reqdrive_req* req) {
  usz i;
  for (i = 0; i < req->path_len && i < cap - 1; i++)
    reqpath[i] = (char)req->path[i];
  reqpath[i] = 0;
}

/* Serve one round of the resolved file's bytes at x->offset, 404 if it
 * does not resolve or open/read. */
static int on_request(void* ctx, wired_http_exchange* x) {
  char resolved[256], reqpath[128];
  ssz  fd, total, got;
  (void)ctx;
  reqpath_copy(reqpath, sizeof reqpath, x->req);
  if (!wired_staticfile_resolve(
          ".", reqpath, "index.html", resolved, sizeof resolved))
    return not_found(x);
  fd = wired_fio_open(resolved);
  if (fd < 0) return not_found(x);
  total = wired_fio_size(resolved);
  got   = wired_fio_pread(
      fd, wired_mspan_of(x->body->p, x->body->cap), x->offset);
  wired_fio_close(fd);
  if (total < 0 || got < 0) return not_found(x);
  if (x->offset == 0) {
    x->content_type = wired_mimetype_for_path(resolved);
    x->total_size   = (u64)total;
  }
  x->body->len = (usz)got;
  if (x->offset + (u64)got < (u64)total) x->more = 1;
  return 1;
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
