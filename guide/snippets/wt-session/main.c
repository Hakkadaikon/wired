#define WIRED_MAIN
#include "wired.h"

/* Log "<prefix><bytes>\n": wired_log_str needs a NUL-terminated string. */
static void log_span(const char* prefix, wired_span s) {
  char line[64];
  usz  n = 0;
  while (*prefix) line[n++] = *prefix++;
  for (usz i = 0; i < s.n && n < sizeof line - 2; i++) line[n++] = (char)s.p[i];
  line[n++] = '\n';
  line[n]   = 0;
  wired_log_str(line);
}

static int is(wired_span s, const char* lit) {
  usz i = 0;
  while (i < s.n && lit[i] == (char)s.p[i]) i++;
  return i == s.n && lit[i] == 0;
}

/* Decide per :path, before the session exists. Leaving `out` untouched
 * accepts; a non-zero status is sent instead of 200. */
static void on_resource(
    void*                       ctx,
    wired_span                  authority,
    wired_span                  path,
    wired_wt_resource_decision* out) {
  (void)ctx;
  (void)authority;
  if (is(path, "/forbidden")) out->status = 404;
}

static void on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  (void)ctx;
  (void)s;
  log_span("session ", path);
  log_span("protocol ", protocol);
}

/* Fires once per session, however it ended. Release per-session state here. */
static void on_session_close(void* ctx, wired_wt_session* s) {
  (void)ctx;
  (void)s;
  wired_log_str("session closed\n");
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static u8        priv[32], pub[32], seed[32], rnd[32];
  static const u8  scid[] = "guide-wt";
  wired_srvboot_id id      = {0};
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x50 + i);
    seed[i] = (u8)(0x90 + i);
    rnd[i]  = (u8)(0xb0 + i);
  }
  wired_x25519_base(pub, priv);
  id.priv                    = priv;
  id.pub                     = pub;
  id.cert_seed               = seed;
  id.random                  = rnd;
  id.scid                    = scid;
  id.scid_len                = sizeof scid - 1; /* without the string's NUL */
  id.max_datagram_frame_size = 65535; /* WebTransport requires DATAGRAM */

  wired_srvrun_opt opt    = {0};
  opt.incoming_cpu        = -1;
  opt.wt_resource_check   = on_resource;
  opt.wt_protocols        = "chat"; /* space-separated list we accept */
  opt.wt_on_session       = on_session;
  opt.wt_on_session_close = on_session_close;

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
