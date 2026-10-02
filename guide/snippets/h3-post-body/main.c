#define WIRED_MAIN
#include "wired.h"

/* App's own request-body cap (RFC 9114 4.1), well under both demo files:
 * anything over this stops the body early and answers 413, same as the
 * SDK's own window overflow would without on_body registered. */
#define APP_BODY_LIMIT 4096

static u64 g_total; /* bytes accumulated for the body in progress */
static int g_active; /* 1 while a body is being accumulated */

/* Log "<prefix><v>\n" -- there is no printf. */
static void log_u64(const char* prefix, u64 v) {
  char             s[21];
  usz              at = 0;
  wired_fmt_u64_in in = {v, 1};
  wired_log_str(prefix);
  wired_fmt_u64(s, &at, &in);
  s[at] = 0;
  wired_log_str(s);
  wired_log_str("\n");
}

/* Streams the request body in (wired_srvloop_on_body's sequencing): one
 * call per DATA chunk, in order, fin=1 on the last. Chunk boundaries follow
 * the client's own QUIC send packetization, which is not fixed run to run
 * -- only the running total is logged, once the body is whole. Returning 0
 * past APP_BODY_LIMIT stops the body and answers 413 -- the handler below
 * is never called for that request. */
static int on_body(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    u64                         stream_id,
    wired_span                  chunk,
    int                         fin) {
  (void)ctx;
  (void)req;
  (void)stream_id;
  if (!g_active) {
    g_total  = 0;
    g_active = 1;
  }
  g_total += chunk.n;
  if (g_total > APP_BODY_LIMIT) {
    g_active = 0;
    return 0;
  }
  if (fin) {
    log_u64("total ", g_total);
    g_active = 0;
  }
  return 1;
}

/* Answers with the body's byte count once on_body has reassembled it
 * whole (g_total holds that count; on_body already logged it). */
static int on_http(void* ctx, wired_http_exchange* x) {
  char             s[21];
  usz              at = 0;
  wired_fmt_u64_in in = {g_total, 1};
  (void)ctx;
  wired_fmt_u64(s, &at, &in);
  s[at++]         = '\n';
  x->content_type = "text/plain";
  memcpy(x->body->p, s, at);
  x->body->len = at;
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

  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h    = {.http = on_http, .on_body = on_body};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run(port, &id, h, obs) ? 0 : 1;
}
