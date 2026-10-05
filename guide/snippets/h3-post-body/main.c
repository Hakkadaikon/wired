#define WIRED_MAIN
#include "wired.h"

/* App's own request-body cap (RFC 9114 4.1), well under both demo files:
 * anything over this stops the body early and answers 413, same as the
 * SDK's own window overflow would without on_body registered. */
#define APP_BODY_LIMIT 4096

static u64 g_total;  /* bytes accumulated for the body in progress */
static int g_active; /* 1 while a body is being accumulated */

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
    wired_dprintf(2, "total %lu\n", g_total);
    g_active = 0;
  }
  return 1;
}

/* Answers with the body's byte count once on_body has reassembled it
 * whole (g_total holds that count; on_body already logged it). */
static int on_http(void* ctx, wired_http_exchange* x) {
  (void)ctx;
  x->content_type = "text/plain";
  wired_obuf_printf(x->body, "%lu\n", g_total);
  return 1;
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-h3");

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {.http = on_http, .on_body = on_body};
  wired_srvrun_obs     obs = {0};
  return wired_server_run(port, &id, h, obs) ? 0 : 1;
}
