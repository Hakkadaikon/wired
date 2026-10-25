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
#include "word_list.h"

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
  if (g_history_len < HISTORY_MAX) {
    g_history[g_history_len++] = '\n';
  }
  for (i = 0; history_room(i, n); i++) {
    g_history[g_history_len++] = body[i];
  }
}

/* History-demo mode (--root absent): RFC 9110 9.3.1 (GET) returns the log;
 * 9.3.3 (POST) appends and echoes. Always returns 200 (matches the wire
 * :status, which srvloop always sends as 200). */
static u64 serve_history(
    const wired_h3reqdrive_req* req, wired_obuf* body_out) {
  if (req->method_len == 4 && req->method[0] == 'P') {
    history_append(req->body, req->body_len);
    body_out->len = 0;
    wired_obuf_put(body_out, wired_span_of(req->body, req->body_len));
    return 200;
  }
  body_out->len = 0;
  wired_obuf_put(body_out, wired_span_of(g_history, g_history_len));
  return 200;
}

/* The request body is a scratch view, so both paths copy out. Always sends a
 * body. Dispatches to static-file or history-demo mode depending on whether
 * --root was given, then logs the request (once, on the first round -- a
 * streamed multi-round static file would otherwise log once per round). */
static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    wired_obuf*                 body_out,
    const char**                content_type,
    int*                        more,
    u64*                        total_size) {
  const app_config* cfg    = (const app_config*)ctx;
  wired_span        method = wired_span_of(req->method, req->method_len);
  wired_span        path   = wired_span_of(req->path, req->path_len);
  u64               status = cfg->root ? wl_serve_static(
                                             cfg, path, offset, body_out, content_type, more,
                                             total_size)
                                       : serve_history(req, body_out);
  if (offset == 0) {
    wl_access_log(cfg, method, path, status, body_out->len);
  }
  return 1;
}

/* 1 if ob holds exactly "hi" (the POST echo). */
static int selfcheck_echo_ok(const wired_obuf* ob, const u8* out) {
  return ob->len == 2 && out[0] == 'h';
}

/* 1 if ob holds exactly "\nhi" (the GET history dump after one POST). */
static int selfcheck_history_ok(const wired_obuf* ob, const u8* out) {
  return ob->len == 3 && out[1] == 'h' && out[2] == 'i';
}

/* Self-check (ponytail: the only non-trivial app logic is the store/echo). */
static void app_selfcheck(void) {
  u8                   out[64];
  wired_obuf           ob           = {out, sizeof out, 0};
  app_config           cfg          = {0};
  const char*          content_type = 0;
  int                  more         = 0;
  u64                  total_size   = 0;
  wired_h3reqdrive_req post         = {
      .method     = (const u8*)"POST",
      .method_len = 4,
      .body       = (const u8*)"hi",
      .body_len   = 2};
  wired_h3reqdrive_req get = {.method = (const u8*)"GET", .method_len = 3};
  g_history_len            = 0;
  app_on_request(&cfg, &post, 0, &ob, &content_type, &more, &total_size);
  if (!selfcheck_echo_ok(&ob, out)) {
    wired_die("selfcheck: echo failed\n");
  }
  app_on_request(&cfg, &get, 0, &ob, &content_type, &more, &total_size);
  if (!selfcheck_history_ok(&ob, out)) {
    wired_die("selfcheck: history failed\n");
  }
  g_history_len = 0;
}

/* Fixed, deterministic server identity for wired_srvdriver_run: X25519
 * handshake key pair, the ECDSA P-256 signing scalar (cert_seed), the server
 * SCID, and a fixed ServerHello random. A demo needs no rotation. */
static void server_identity(wired_srvboot_id* id, wired_srvboot_demo_keys* k) {
  wired_srvboot_demo(id, k, 0x40, "CLISCI");
  id->max_datagram_frame_size = 65535;
  /* RFC 8446 4.6.1: the seed append_ticket_frame (respond.c) derives its
   * rotating ticket keys from -- opening derives the same keys. */
  id->ticket_key = wired_srvloop_ticket_key();
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
  if (!wired_srvdriver_parse(argc, argv, &cfg->driver)) {
    wired_die("bad driver flag combination\n");
  }
  cfg->driver.run.busy_poll =
      (int)wired_cliargs_int(argc, argv, "--busy-poll", 0);
  cfg->driver.run.incoming_cpu = -1;
}

/* RFC 9000 9.6 (quic-interop-runner connectionmigration): the sim
 * network's fixed server addresses, advertised as the preferred_address so
 * a client can perform an active migration onto its spare CID.
 * ponytail: fixed interop-sim literals behind one flag, no address parser
 * -- a deployment wanting real values sets wired_srvboot_id's pref_*
 * fields from its own configuration. */
static const u8 g_migrate_v4[4]  = {193, 167, 100, 100};
static const u8 g_migrate_v6[16] = {0xfd, 0x00, 0xca, 0xfe, 0xca, 0xfe,
                                    0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x01, 0x00};

/* Port 4433, not 443: the preferred address must name a path DIFFERENT
 * from the one in use, or no client ever migrates -- the runner's client
 * dials the dual-stack name, so whichever family it lands on, the same
 * address at 443 would be its current path (observed live: ngtcp2 either
 * selected its current address and stayed put, or declined the
 * cross-family alternative). The interop image REDIRECTs udp/4433 to this
 * server's single 443 socket (run_endpoint.sh); conntrack rewrites the
 * replies' source back to 4433, so the client sees the server answering
 * from the preferred address as RFC 9000 9.6.2 requires. */
static void app_pref_addr(wired_srvboot_id* id, int argc, char** argv) {
  if (!wired_cliargs_flag(argc, argv, "--migrate-addr")) {
    return;
  }
  id->pref_v4      = g_migrate_v4;
  id->pref_v6      = g_migrate_v6;
  id->pref_v4_port = 4433;
  id->pref_v6_port = 4433;
}

/* Optional transport tuning; 0 keeps the built-in defaults (server_tp.c). */
static void app_transport_tuning(wired_srvboot_id* id, int argc, char** argv) {
  id->max_data         = (u64)wired_cliargs_int(argc, argv, "--max-data", 0);
  id->max_streams_bidi = (u64)wired_cliargs_int(argc, argv, "--max-streams", 0);
  /* RFC 7301 3.2: the interop image keeps the client's ALPN order (msquic
   * offers [hq-interop, h3] and then speaks hq-interop regardless). */
  id->alpn_client_order = wired_cliargs_flag(argc, argv, "--alpn-client-order");
  app_pref_addr(id, argc, argv);
}

/* qlog/keylog paths, the cert pair SIGHUP re-reads, and the CC algorithm. */
static wired_srvrun_obs app_obs(const app_config* cfg, int argc, char** argv) {
  return (wired_srvrun_obs){
      wired_cliargs_str(argc, argv, "--qlog-file", 0),
      wired_cliargs_str(argc, argv, "--keylog-file", 0), cfg->cert_path,
      cfg->key_path,
      /* CC_ALGO_*: 0 NewReno (default), 1 Cubic, 2 BBR */
      (int)wired_cliargs_int(argc, argv, "--cc-algo", 0)};
}

/* The real entry point, called from _start (see wired.h's WIRED_MAIN block)
 * with argc/argv recovered from the kernel stack. */
int wired_main(int argc, char** argv) {
  wired_srvboot_id        id = {0};
  wired_srvboot_demo_keys keys;
  app_config              cfg = {0};
  wired_srvrun_handler    h   = {.cb = app_on_request, .ctx = &cfg};
  app_selfcheck();
  load_config(&cfg, argc, argv);
  server_identity(&id, &keys);
  app_transport_tuning(&id, argc, argv);
  wired_certreload_load_or_selfsigned(
      cfg.cert_path, cfg.key_path, &cert_store, &id);
  if (!wired_srvdriver_run(&id, h, app_obs(&cfg, argc, argv), &cfg.driver)) {
    wired_die("listen failed\n");
  }
  return 0;
}
