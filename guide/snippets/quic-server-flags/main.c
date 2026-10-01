#define WIRED_MAIN
#include "wired.h"

/* Unused here: the client below only does TLS handshakes, no requests. */
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
  (void)body_out;
  (void)content_type;
  (void)more;
  (void)total_size;
  return 0;
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static u8        priv[32], pub[32], seed[32], rnd[32];
  static const u8  scid[] = "guide-h3";
  wired_srvboot_id id      = {0};
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

  /* --port, --workers, --cores, --ifindex, ... pick and configure a driver. */
  wired_srvdriver_opt opt = {0};
  if (!wired_srvdriver_parse(argc, argv, &opt)) {
    wired_log_str("bad flags\n");
    return 2;
  }
  wired_srvrun_handler h   = {on_request, 0, 0, 0};
  wired_srvrun_obs     obs = {0};
  return wired_srvdriver_run(&id, h, obs, &opt) < 0 ? 1 : 0;
}
