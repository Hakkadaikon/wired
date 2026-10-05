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
  static const char* const lines[TICKS_SHOWN] = {
      "tick 1\n", "tick 2\n", "tick 3\n"};
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
  wired_obuf_printf(body_out, "ok");
  return 1;
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-h3");

  wired_srvrun_opt opt = {0};
  opt.incoming_cpu     = -1;
  opt.on_step          = on_step;

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {.cb = on_request};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
