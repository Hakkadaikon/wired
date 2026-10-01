#define WIRED_MAIN
#include "wired.h"

/* An app timer, independent of any connection: wired_srvrun_opt.on_step
 * fires at least every SRVRUN_PTO_MS (25ms) once registered, whether or
 * not any connection is live. Logged only for the first few ticks so the
 * golden output stays a fixed length regardless of how long the server
 * actually ran. */
#define TICKS_SHOWN 3
static int g_ticks = 0;

static void on_step(void* ctx, u64 now_ms) {
  static const char* const lines[TICKS_SHOWN] = {"tick 1\n", "tick 2\n", "tick 3\n"};
  (void)ctx;
  (void)now_ms;
  if (g_ticks >= TICKS_SHOWN) return;
  wired_log_str(lines[g_ticks]);
  g_ticks++;
}

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
  *content_type = "text/plain";
  memcpy(body_out->p, "ok", 2);
  body_out->len = 2;
  return 1;
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
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

  wired_srvrun_opt opt = {0};
  opt.incoming_cpu      = -1;
  opt.on_step           = on_step;

  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h    = {on_request, 0, 0};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
