#define WIRED_MAIN
#include "wired.h"

/* The whole point of this page: wired_staticfile_resolve rejects path
 * traversal and picks an index file for a directory request, then
 * wired_mimetype_for_path infers the Content-Type from the resolved
 * file's extension. */

static int not_found(wired_http_exchange* x) {
  x->status       = 404;
  x->content_type = "text/plain";
  wired_obuf_printf(x->body, "not found");
  return 1;
}

/* Serve one round of the resolved file's bytes at x->offset, 404 if it
 * does not resolve or open/read. */
static int on_request(void* ctx, wired_http_exchange* x) {
  char resolved[256], reqpath[128];
  ssz  fd, total, got;
  (void)ctx;
  wired_span_to_cstr(reqpath, sizeof reqpath, wired_h3req_path(x->req));
  if (!wired_staticfile_resolve(
          ".", reqpath, "index.html", resolved, sizeof resolved))
    return not_found(x);
  fd = wired_fio_open(resolved);
  if (fd < 0) return not_found(x);
  total = wired_fio_size(resolved);
  got =
      wired_fio_pread(fd, wired_mspan_of(x->body->p, x->body->cap), x->offset);
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
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-h3");

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {.http = on_request};
  wired_srvrun_obs     obs = {0};
  return wired_server_run(port, &id, h, obs) ? 0 : 1;
}
