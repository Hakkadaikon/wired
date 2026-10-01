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

/* Greet every new session on a server-opened uni stream. Its bytes must start
 * with the WebTransport stream signal naming the session. */
static void on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  (void)ctx;
  (void)protocol;
  log_span("session ", path);
  u8  buf[16];
  usz n = wired_wtwire_signal_put(buf, sizeof buf, 0, s->connect_stream_id);
  memcpy(buf + n, "welcome", 7);
  wired_server_wt_open_uni(s, wired_span_of(buf, n + 7));
}

/* Echo a client-opened bidi stream once it has been fully received. */
static void on_stream_data(
    void* ctx, wired_wt_session* s, u64 stream_id, wired_span data, int fin) {
  (void)ctx;
  if (!fin) return;
  log_span("stream ", data);
  wired_server_wt_stream_reply(s, stream_id, data);
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

  wired_srvrun_opt opt  = {0};
  opt.incoming_cpu      = -1;
  opt.wt_on_session     = on_session;
  opt.wt_on_stream_data = on_stream_data;

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
