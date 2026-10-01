#define WIRED_MAIN
#include "wired.h"

/* Called once per request (and again while *more is set). Fill body_out and
 * return 1 to answer 200. */
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
  wired_log_str("request /\n");
  *content_type = "text/plain";
  memcpy(body_out->p, "hello", 5);
  body_out->len = 5;
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
  wired_srvrun_handler h    = {on_request, 0, 0};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run(port, &id, h, obs) ? 0 : 1;
}
