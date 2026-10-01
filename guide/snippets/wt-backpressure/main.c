#define WIRED_MAIN
#include "wired.h"

static int is(wired_span s, const char* lit) {
  usz i = 0;
  while (i < s.n && lit[i] == (char)s.p[i]) i++;
  return i == s.n && lit[i] == 0;
}

static void log_bool(const char* prefix, int v) {
  wired_log_str(prefix);
  wired_log_str(v ? "1\n" : "0\n");
}

/* A server-opened stream, kept open, whose inflight state the client's
 * second round below resets. */
static i64 g_uni   = -1;
static int g_held  = 0;

static void on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  (void)ctx;
  (void)path;
  (void)protocol;
  u8  buf[16];
  usz n = wired_wtwire_signal_put(buf, sizeof buf, 0, s->connect_stream_id);
  memcpy(buf + n, "ready", 5);
  g_uni = wired_server_wt_open_uni_stream(s, wired_span_of(buf, n + 5));
}

/* An upload split across two writes: hold receive credit on the first
 * (pausing the peer's send window -- bytes it already has credit for
 * still arrive, nothing new is granted), release once it ends with FIN.
 * The final round's word then exercises reset + inflight on g_uni. */
static void on_stream_data(
    void* ctx, wired_wt_session* s, u64 stream_id, wired_span data, int fin) {
  (void)ctx;
  if (!fin) {
    if (!g_held) {
      wired_server_wt_stream_hold(s, stream_id, 1);
      wired_log_str("held\n");
      g_held = 1;
    }
    return;
  }
  if (g_held) {
    wired_server_wt_stream_hold(s, stream_id, 0);
    wired_log_str("released\n");
    g_held = 0;
  }
  if (is(data, "abort")) {
    wired_server_wt_stream_reset(s, (u64)g_uni, 1);
    wired_log_str("reset\n");
  }
  log_bool("inflight ", wired_server_wt_stream_inflight(s, (u64)g_uni));
  wired_server_wt_stream_reply(s, stream_id, wired_span_of((const u8*)"ok", 2));
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static u8       priv[32], pub[32], seed[32], rnd[32];
  static const u8 scid[] = "guide-wt";
  wired_srvboot_id id = {0};
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

  wired_srvrun_opt opt  = {0};
  opt.incoming_cpu      = -1;
  opt.wt_on_session     = on_session;
  opt.wt_on_stream_data = on_stream_data;

  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h    = {0};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
