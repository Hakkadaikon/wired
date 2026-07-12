/* Real-UDP HTTP/3 server. libc-free, x86_64-linux, direct syscalls, driven by
 * the single SDK header <wired.h>.
 *
 * The whole server -- bind, receive, cold-start each client Initial, drive
 * the handshake, answer HTTP/3 requests, seal every reply -- lives in the
 * SDK (wired_srvdriver_run). This file is just the application: a message
 * log (POST appends and echoes, GET returns the whole log) or, with --root,
 * a static file server; the demo server identity; and CLI configuration. See
 * examples/README.md for what completes here vs. what an external HTTP/3
 * client additionally needs.
 *
 * Four ways to run it, chosen by CLI flags at startup and resolved by
 * wired_srvdriver_parse (mutually exclusive, see srvdriver.h): plain
 * single-process UDP (the default), multi-worker (--workers N), AF_XDP
 * (--ifindex N --ip a.b.c.d), or thread-based fan-out (--cores a,b,c). */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim and _start */
#include "app/http3/server/srvdriver/srvdriver.h"
#include "common/platform/exit/exit.h"
#include "wired.h"

/* In-memory message store. POST bodies are appended (newline-separated); GET
 * returns the whole log. Outside the connection state on purpose: re-initing
 * a connection (RFC 9000 7) does NOT clear it, so a POST is visible to a
 * later GET on a reconnect.
 * ponytail: fixed 8 KiB, in-RAM only -- a POST past the cap is truncated. */
#define HISTORY_MAX 8192
static u8  g_history[HISTORY_MAX];
static usz g_history_len;

/* 1 while there is room left in g_history and body[i] is still in range. */
static int history_room(usz i, usz n) {
  return i < n && g_history_len < HISTORY_MAX;
}

/* RFC 9110 9.3.3: append the POST body, newline-separated, truncating at cap.
 */
static void history_append(const u8* body, usz n) {
  usz i;
  if (g_history_len < HISTORY_MAX) g_history[g_history_len++] = '\n';
  for (i = 0; history_room(i, n); i++) g_history[g_history_len++] = body[i];
}

/* Copy up to out->cap bytes of src into out, setting out->len to the count
 * copied. */
static void copy_capped(quic_obuf* out, quic_span src) {
  usz i;
  for (i = 0; i < src.n && i < out->cap; i++) out->p[i] = src.p[i];
  out->len = i;
}

/* Application/driver configuration, resolved once at startup from argv and
 * handed to app_on_request as its opaque ctx. --root selects static file
 * mode; absent, the demo history mode runs unchanged (back-compat). driver
 * carries which of the four run paths wired_srvdriver_run takes. */
typedef struct {
  const char*         root;       /**< document root, or 0 for history mode */
  const char*         index;      /**< index file name for dir requests */
  const char*         access_log; /**< access log path, or 0 to disable */
  const char*         cert_path;  /**< cert.pem path (--cert) */
  const char*         key_path;   /**< key.pem path (--key) */
  wired_srvdriver_opt driver;     /**< resolved driver selection + knobs */
} app_config;

/* Append span's bytes to line at *at, stopping at cap. */
static void log_append_span(char* line, usz cap, usz* at, quic_span span) {
  usz i;
  for (i = 0; i < span.n && *at < cap; i++) line[(*at)++] = (char)span.p[i];
}

/* One line per request: "METHOD PATH STATUS BYTES\n" (ponytail: fixed
 * single-line format, no log levels/rotation -- add if an operator needs it).
 */
static void access_log(
    const app_config* cfg,
    quic_span         method,
    quic_span         path,
    u64               status,
    u64               nbytes) {
  char line[512];
  usz  at = 0;
  if (!cfg->access_log) return;
  log_append_span(line, sizeof line - 1, &at, method);
  line[at++] = ' ';
  log_append_span(line, sizeof line - 40, &at, path);
  line[at++] = ' ';
  wired_fmt_u64(line, &at, &(wired_fmt_u64_in){status, 1});
  line[at++] = ' ';
  wired_fmt_u64(line, &at, &(wired_fmt_u64_in){nbytes, 1});
  line[at++] = '\n';
  wired_fio_append(cfg->access_log, quic_span_of((const u8*)line, at));
}

/* Write the 404 body and return its status code. */
static u64 not_found(quic_obuf* body_out) {
  copy_capped(body_out, quic_span_of((const u8*)"404 Not Found\n", 14));
  return 404;
}

/* NUL-terminate path into reqpath (cap-1 bytes max). */
static void reqpath_copy(char* reqpath, usz cap, quic_span path) {
  usz i;
  for (i = 0; i < path.n && i < cap - 1; i++) reqpath[i] = (char)path.p[i];
  reqpath[i] = 0;
}

/* Static-file mode (quiche-server's --root/--index): resolve the request path
 * under cfg->root and serve the file's bytes, or a 404 body when it does not
 * resolve/open (the wire :status stays 200 -- see srvloop/respond.c, which
 * hard-codes 200 for every decoded request; changing that is a larger,
 * separate change). The logged status reflects whether the file was found. */
static u64 serve_static(
    const app_config* cfg,
    quic_span         path,
    quic_obuf*        body_out,
    const char**      content_type) {
  char resolved[512];
  char reqpath[400];
  ssz  n;
  reqpath_copy(reqpath, sizeof reqpath, path);
  if (!wired_staticfile_resolve(
          cfg->root, reqpath, cfg->index, resolved, sizeof resolved))
    return not_found(body_out);
  n = wired_fio_read(resolved, quic_mspan_of(body_out->p, body_out->cap));
  if (n < 0) return not_found(body_out);
  body_out->len = (usz)n;
  *content_type = wired_mimetype_for_path(resolved);
  return 200;
}

/* History-demo mode (--root absent): RFC 9110 9.3.1 (GET) returns the log;
 * 9.3.3 (POST) appends and echoes. Always returns 200 (matches the wire
 * :status, which srvloop always sends as 200). */
static u64 serve_history(const wired_h3reqdrive_req* req, quic_obuf* body_out) {
  if (req->method_len == 4 && req->method[0] == 'P') {
    history_append(req->body, req->body_len);
    copy_capped(body_out, quic_span_of(req->body, req->body_len));
    return 200;
  }
  copy_capped(body_out, quic_span_of(g_history, g_history_len));
  return 200;
}

/* The request body is a scratch view, so both paths copy out. Always sends a
 * body. Dispatches to static-file or history-demo mode depending on whether
 * --root was given, then logs the request. */
static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    quic_obuf*                  body_out,
    const char**                content_type) {
  const app_config* cfg    = (const app_config*)ctx;
  quic_span         method = quic_span_of(req->method, req->method_len);
  quic_span         path   = quic_span_of(req->path, req->path_len);
  u64 status = cfg->root ? serve_static(cfg, path, body_out, content_type)
                         : serve_history(req, body_out);
  access_log(cfg, method, path, status, body_out->len);
  return 1;
}

/* 1 if ob holds exactly "hi" (the POST echo). */
static int selfcheck_echo_ok(const quic_obuf* ob, const u8* out) {
  return ob->len == 2 && out[0] == 'h';
}

/* 1 if ob holds exactly "\nhi" (the GET history dump after one POST). */
static int selfcheck_history_ok(const quic_obuf* ob, const u8* out) {
  return ob->len == 3 && out[1] == 'h' && out[2] == 'i';
}

/* Self-check (ponytail: the only non-trivial app logic is the store/echo). */
static void app_selfcheck(void) {
  u8                   out[64];
  quic_obuf            ob           = {out, sizeof out, 0};
  app_config           cfg          = {0};
  const char*          content_type = 0;
  wired_h3reqdrive_req post         = {
              .method     = (const u8*)"POST",
              .method_len = 4,
              .body       = (const u8*)"hi",
              .body_len   = 2};
  wired_h3reqdrive_req get = {.method = (const u8*)"GET", .method_len = 3};
  g_history_len            = 0;
  app_on_request(&cfg, &post, &ob, &content_type);
  if (!selfcheck_echo_ok(&ob, out)) wired_die("selfcheck: echo failed\n");
  app_on_request(&cfg, &get, &ob, &content_type);
  if (!selfcheck_history_ok(&ob, out))
    wired_die("selfcheck: history failed\n");
  g_history_len = 0;
}

/* Fixed, deterministic server identity for wired_srvdriver_run: X25519
 * handshake key pair, the ECDSA P-256 signing scalar (cert_seed), the server
 * SCID, and a fixed ServerHello random. A demo needs no rotation. */
static const u8 SERVER_SCID[6] = {'C', 'L', 'I', 'S', 'C', 'I'};

/* The demo server's fixed key material buffers, owned by the caller
 * (wired_main) so they outlive wired_srvdriver_run. */
typedef struct {
  u8 priv[32];
  u8 pub[32];
  u8 seed[32];
  u8 rnd[32];
} server_keys;

static void server_identity(wired_srvboot_id* id, server_keys* k) {
  for (usz i = 0; i < 32; i++) {
    k->priv[i] = (u8)(0x40 + i);
    k->seed[i] = (u8)(0x80 + i);
    k->rnd[i]  = (u8)(0xa0 + i);
  }
  quic_x25519_base(k->pub, k->priv);
  id->priv        = k->priv;
  id->pub         = k->pub;
  id->cert_seed   = k->seed;
  id->scid        = SERVER_SCID;
  id->scid_len    = sizeof SERVER_SCID;
  id->random      = k->rnd;
  id->chain       = 0; /* self-signed; see README.md for an external chain */
  id->chain_count = 0;
  id->max_data    = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 65535;
  id->san_ipv4                = 0;
  id->now_secs                = 0;
}

/* Optional drop-in certificate: cert.pem (fullchain, leaf first, at most 2
 * certificates) and key.pem (P-256 private key), default paths overridable
 * via --cert/--key; static because the identity holds views into it for the
 * whole run, and a later SIGHUP reload (srvrun.c) reuses the same paths. */
static wired_certreload_store cert_store;

/* Resolve CLI configuration: --port (default 4433), --root (static file
 * mode, absent = history demo), --index (default index.html), --access-log
 * (absent = no logging), --cert/--key (cert.pem/key.pem in the cwd by
 * default), and the driver selection (--workers/--pin-cores, --ifindex/
 * --queue/--ip/--skb-mode, --cores/--control-core, --pin-core, --busy-poll).
 * qlog/keylog paths go straight into the wired_srvrun_obs built in
 * wired_main and are passed through by wired_srvdriver_run to every driver
 * except WORKERS. */
static void load_config(app_config* cfg, int argc, char** argv) {
  cfg->root       = wired_cliargs_str(argc, argv, "--root", 0);
  cfg->index      = wired_cliargs_str(argc, argv, "--index", "index.html");
  cfg->access_log = wired_cliargs_str(argc, argv, "--access-log", 0);
  /* wired_certreload_load_or_selfsigned dies if cert_path is set but the
   * load fails, so --cert has no implicit "cert.pem in the cwd" default
   * (unlike --index/--access-log) -- pass --cert/--key explicitly to load
   * a real certificate; absent, the demo stays self-signed. */
  cfg->cert_path = wired_cliargs_str(argc, argv, "--cert", 0);
  cfg->key_path  = wired_cliargs_str(argc, argv, "--key", "key.pem");
  if (!wired_srvdriver_parse(argc, argv, &cfg->driver))
    wired_die("bad driver flag combination\n");
  cfg->driver.run.busy_poll =
      (int)wired_cliargs_int(argc, argv, "--busy-poll", 0);
  cfg->driver.run.incoming_cpu = -1;
}

/* The real entry point, called from _start (see wired.h's WIRED_MAIN block)
 * with argc/argv recovered from the kernel stack. */
int wired_main(int argc, char** argv) {
  wired_srvboot_id     id;
  server_keys          keys;
  app_config           cfg = {0};
  wired_srvrun_handler h   = {app_on_request, &cfg};
  wired_srvrun_obs     obs;
  app_selfcheck();
  load_config(&cfg, argc, argv);
  server_identity(&id, &keys);
  wired_certreload_load_or_selfsigned(
      cfg.cert_path, cfg.key_path, &cert_store, &id);
  obs = (wired_srvrun_obs){
      wired_cliargs_str(argc, argv, "--qlog-file", 0),
      wired_cliargs_str(argc, argv, "--keylog-file", 0), cfg.cert_path,
      cfg.key_path, 0};
  if (!wired_srvdriver_run(
          (u16)wired_cliargs_int(argc, argv, "--port", 4433), &id, h, obs,
          &cfg.driver))
    wired_die("listen failed\n");
  return 0;
}
