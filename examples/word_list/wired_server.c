/* Real-UDP HTTP/3 server. libc-free, x86_64-linux, direct syscalls, own _start,
 * static. Driven by the single SDK header <wired.h>.
 *
 * The whole server — bind, receive, cold-start each client Initial, drive the
 * handshake, answer HTTP/3 requests, seal every reply — is wired_server_run.
 * This file is just the application: a message log (POST appends and echoes,
 * GET returns the whole log) or, with --root, a static file server; the demo
 * server identity; CLI configuration; and the freestanding entry point. See
 * examples/README.md for what completes here vs. what an external HTTP/3
 * client additionally needs.
 *
 * Three ways to run it, chosen by CLI flags at startup (mutually exclusive):
 * plain single-process UDP (the default), multi-worker (--workers N, fork +
 * SO_REUSEPORT, tasks/core-pinning-plan.md), or AF_XDP (--ifindex N --ip
 * a.b.c.d, tasks/xdp-driver-plan.md). All three drive the same application
 * logic below. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "wired.h"

#include "app/http3/server/srvworkers/srvworkers.h"

/* A fatal error: print and exit (freestanding, no libc atexit). */
static void die(const char* msg) {
  wired_log_str(msg);
  syscall1(SYS_exit, 1);
}

/* In-memory message store. POST bodies are appended (newline-separated); GET
 * returns the whole log. Outside the connection state on purpose: re-initing a
 * connection (RFC 9000 7) does NOT clear it, so a POST is visible to a later
 * GET on a reconnect.
 * ponytail: fixed 8 KiB, in-RAM only — a POST past the cap is truncated. */
#define HISTORY_MAX 8192
static u8  g_history[HISTORY_MAX];
static usz g_history_len;

/* RFC 9110 9.3.3: append the POST body, newline-separated, truncating at cap.
 */
static void history_append(const u8* body, usz n) {
  usz i;
  if (g_history_len < HISTORY_MAX) g_history[g_history_len++] = '\n';
  for (i = 0; i < n && g_history_len < HISTORY_MAX; i++)
    g_history[g_history_len++] = body[i];
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
 * selects which of the three run paths wired_main takes. */
typedef enum { DRIVER_PLAIN, DRIVER_WORKERS, DRIVER_XDP } driver_kind;

typedef struct {
  const char* root;        /**< document root, or 0 for history-demo mode */
  const char* index;       /**< index file name for directory requests */
  const char* access_log;  /**< access log path, or 0 to disable logging */
  const char* qlog_path;   /**< qlog file path, or 0 to disable */
  const char* keylog_path; /**< NSS key log file path, or 0 to disable */
  const char* cert_path;   /**< cert.pem path (--cert, default cert.pem) */
  const char* key_path;    /**< key.pem path (--key, default key.pem) */
  int         busy_poll;   /**< --busy-poll: 1 = MSG_DONTWAIT spin loop */
  u16         port;        /**< --port, default 4433 */
  driver_kind      driver; /**< which of the three run paths to take */
  wired_srvworkers_opt workers; /**< --workers/--pin-cores, DRIVER_WORKERS */
  wired_srvxdp_cfg      xdp;    /**< --ifindex/--queue/--ip/--skb-mode */
} app_config;

/* One line per request: "METHOD PATH STATUS BYTES\n" (ponytail: fixed
 * single-line format, no log levels/rotation — add if an operator needs it).
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
  for (usz i = 0; i < method.n && at < sizeof line - 1; i++)
    line[at++] = (char)method.p[i];
  line[at++] = ' ';
  for (usz i = 0; i < path.n && at < sizeof line - 40; i++)
    line[at++] = (char)path.p[i];
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

/* Static-file mode (quiche-server's --root/--index): resolve the request path
 * under cfg->root and serve the file's bytes, or a 404 body when it does not
 * resolve/open (the wire :status stays 200 — see srvloop/respond.c, which
 * hard-codes 200 for every decoded request; changing that is a larger,
 * separate change). The logged status reflects whether the file was found. */
static u64 serve_static(
    const app_config* cfg,
    quic_span         path,
    quic_obuf*        body_out,
    const char**      content_type) {
  char resolved[512];
  char reqpath[400];
  usz  i;
  ssz  n;
  for (i = 0; i < path.n && i < sizeof reqpath - 1; i++)
    reqpath[i] = (char)path.p[i];
  reqpath[i] = 0;
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
  if (ob.len != 2 || out[0] != 'h') die("selfcheck: echo failed\n");
  app_on_request(&cfg, &get, &ob, &content_type);
  if (ob.len != 3 || out[1] != 'h' || out[2] != 'i')
    die("selfcheck: history failed\n");
  g_history_len = 0;
}

/* Fixed, deterministic server identity for wired_server_run: X25519 handshake
 * key pair, the ECDSA P-256 signing scalar (cert_seed), the server SCID, and a
 * fixed ServerHello random. A demo needs no rotation. */
static const u8 SERVER_SCID[6] = {'C', 'L', 'I', 'S', 'C', 'I'};

/* The demo server's fixed key material buffers, owned by the caller (_start)
 * so they outlive wired_server_run. */
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
  id->priv                    = k->priv;
  id->pub                     = k->pub;
  id->cert_seed               = k->seed;
  id->scid                    = SERVER_SCID;
  id->scid_len                = sizeof SERVER_SCID;
  id->random                  = k->rnd;
  id->chain                   = 0; /* self-signed; see README.md for an external chain */
  id->chain_count             = 0;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 65535;
  id->san_ipv4                = 0;
  id->now_secs                = 0;
}

/* Optional drop-in certificate: cert.pem (fullchain, leaf first, at most 2
 * certificates) and key.pem (P-256 private key), default paths overridable
 * via --cert/--key. wired_certreload_load (app/http3/server/certreload) does
 * the actual PEM/DER decode; store is static because the identity holds
 * views into it for the whole run, and a later SIGHUP reload (srvrun.c)
 * reuses the very same loader against the same paths. */
static wired_certreload_store cert_store;

static void log_chain(usz n) {
  wired_log_str(n == 2 ? "cert.pem: 2 certs\n" : "cert.pem: 1 cert\n");
}

/* 1 if path opens and reads at least one byte (existence probe only; the
 * byte itself is discarded — wired_certreload_load re-reads the whole file
 * right after). WIRED_FIO_ETOOBIG counts as present too: it means the 1-byte
 * probe buffer filled and the file still had more data, i.e. the file exists
 * and is larger than a byte (every real cert/key is). */
static int cert_file_present(const char* path) {
  u8  probe[1];
  ssz r = wired_fio_read(path, quic_mspan_of(probe, sizeof probe));
  return r >= 0 || r == WIRED_FIO_ETOOBIG;
}

/* Drop-in loader: neither cert_path nor key_path present (no --cert/--key
 * and no cert.pem/key.pem in the cwd) keeps the self-signed identity; a
 * broken or half-present pair dies rather than silently serving
 * self-signed. */
static void load_cert_files(
    wired_srvboot_id* id, const char* cert_path, const char* key_path) {
  if (!cert_file_present(cert_path) && !cert_file_present(key_path)) {
    wired_log_str("self-signed (no cert.pem)\n");
    return;
  }
  if (!wired_certreload_load(cert_path, key_path, &cert_store, id))
    die("bad cert.pem/key.pem\n");
  log_chain(id->chain_count);
}

/* One decimal digit of a.b.c.d, or -1 if c is not '0'..'9'. */
static int ipoctet_digit(char c) {
  return (c >= '0' && c <= '9') ? c - '0' : -1;
}

/* One accumulate step for ipoctet_parse's loop; -1 signals "stop" (a
 * non-digit or already out of 0..255 range). */
static int ipoctet_step(int acc, char c) {
  int d = ipoctet_digit(c);
  if (d < 0) return -1;
  return (acc < 0 ? 0 : acc) * 10 + d;
}

/* 0..255, the only range a byte octet can hold. */
static int ipoctet_in_range(int v) { return v >= 0 && v <= 255; }

/* Parse one 0..255 octet starting at s[*i], stopping at '.' or NUL; advances
 * *i past the consumed digits. -1 on empty or out-of-range input (no libc
 * inet_aton available). */
static int ipoctet_parse(const char* s, usz* i) {
  int v = -1;
  int next;
  while ((next = ipoctet_step(v, s[*i])) >= 0) {
    v = next;
    (*i)++;
  }
  return ipoctet_in_range(v) ? v : -1;
}

/* 1 if s[i] is the '.' separator expected before octet k<3; advances i past
 * it. 0 (malformed) if it is missing. */
static int ipaddr_sep(const char* s, usz* i, usz k) {
  if (k >= 3) return 1;
  if (s[*i] != '.') return 0;
  (*i)++;
  return 1;
}

/* One octet-then-separator step of ipaddr_parse's loop: parses out[k] and
 * consumes the following '.' (k<3) or nothing (k==3). 0 on any malformed
 * octet/separator. */
static int ipaddr_step(const char* s, usz* i, usz k, u8 out[4]) {
  int v = ipoctet_parse(s, i);
  if (v < 0) return 0;
  out[k] = (u8)v;
  return ipaddr_sep(s, i, k);
}

/* Parse "a.b.c.d" into out[0..3]; returns 1 on success, 0 on any malformed
 * octet (dies at the call site — a bad --ip is a fatal config error). */
static int ipaddr_parse(const char* s, u8 out[4]) {
  usz i = 0;
  for (usz k = 0; k < 4; k++)
    if (!ipaddr_step(s, &i, k, out)) return 0;
  return 1;
}

/* Both chars nonzero and equal: the "still matching" predicate, so
 * cliargs_streq's while carries only one condition. */
static int cliargs_char_match(char a, char b) { return a && b && a == b; }

/* NUL-terminated ascii compare, no libc strcmp available. */
static int cliargs_streq(const char* a, const char* b) {
  usz i = 0;
  while (cliargs_char_match(a[i], b[i])) i++;
  return a[i] == b[i];
}

/* 1 if flag appears anywhere in argv (presence-only switch, e.g.
 * --skb-mode); wired_cliargs_str needs a following element so it cannot
 * detect a flag given last with nothing after it. */
static int cliargs_flag(int argc, char** argv, const char* flag) {
  int i;
  for (i = 0; i < argc; i++)
    if (cliargs_streq(argv[i], flag)) return 1;
  return 0;
}

/* --workers and --ifindex select different SDK entry points and cannot
 * compose; the && lives here so load_config_driver's own branching stays a
 * flat if/if/return chain. */
static int driver_conflict(int has_workers, int has_xdp) {
  return has_workers && has_xdp;
}

/* Selects the driver once has_workers/has_xdp are known to not both hold. */
static driver_kind driver_select(int has_workers, int has_xdp) {
  if (has_xdp) return DRIVER_XDP;
  if (has_workers) return DRIVER_WORKERS;
  return DRIVER_PLAIN;
}

/* Which driver --workers/--ifindex select; dies on both given together. */
static driver_kind load_config_driver(int argc, char** argv) {
  int has_workers = wired_cliargs_int(argc, argv, "--workers", -1) >= 0;
  int has_xdp     = wired_cliargs_int(argc, argv, "--ifindex", -1) >= 0;
  if (driver_conflict(has_workers, has_xdp))
    die("--workers and --ifindex are exclusive\n");
  return driver_select(has_workers, has_xdp);
}

/* --ifindex is required (no sensible default interface); a missing one is a
 * fatal config error. */
static void load_config_xdp_ifindex(
    wired_srvxdp_cfg* xdp, int argc, char** argv) {
  i64 ifindex = wired_cliargs_int(argc, argv, "--ifindex", -1);
  if (ifindex < 0) die("--ifindex is required\n");
  xdp->ifindex = (u32)ifindex;
}

/* --ip is required (no sensible default address); a missing/malformed one is
 * a fatal config error. */
static void load_config_xdp_ip(wired_srvxdp_cfg* xdp, int argc, char** argv) {
  if (!ipaddr_parse(wired_cliargs_str(argc, argv, "--ip", ""), xdp->ip))
    die("--ip a.b.c.d is required\n");
}

/* attach_flags: 0 = native XDP, 2 (XDP_FLAGS_SKB_MODE) = generic mode for
 * drivers/veth without native XDP support. */
static void load_config_xdp(app_config* cfg, int argc, char** argv) {
  load_config_xdp_ifindex(&cfg->xdp, argc, argv);
  load_config_xdp_ip(&cfg->xdp, argc, argv);
  cfg->xdp.queue_id     = (u32)wired_cliargs_int(argc, argv, "--queue", 0);
  cfg->xdp.port         = cfg->port;
  cfg->xdp.bind_flags   = 0;
  cfg->xdp.attach_flags = cliargs_flag(argc, argv, "--skb-mode") ? 2u : 0u;
}

/* Resolve CLI configuration: --port (default 4433), --root (static file mode,
 * absent = history demo), --index (default index.html), --access-log
 * (absent = no logging), --qlog-file / --keylog-file (absent = disabled),
 * --cert / --key (cert.pem/key.pem in the cwd by default), --busy-poll
 * (absent = 0, tasks/polling-driver-plan.md Phase 3), and the driver
 * selection (--workers/--pin-cores, tasks/core-pinning-plan.md; --ifindex/
 * --queue/--ip/--skb-mode, tasks/xdp-driver-plan.md). */
static void load_config(app_config* cfg, int argc, char** argv) {
  cfg->root        = wired_cliargs_str(argc, argv, "--root", 0);
  cfg->index       = wired_cliargs_str(argc, argv, "--index", "index.html");
  cfg->access_log  = wired_cliargs_str(argc, argv, "--access-log", 0);
  cfg->qlog_path   = wired_cliargs_str(argc, argv, "--qlog-file", 0);
  cfg->keylog_path = wired_cliargs_str(argc, argv, "--keylog-file", 0);
  cfg->cert_path   = wired_cliargs_str(argc, argv, "--cert", "cert.pem");
  cfg->key_path    = wired_cliargs_str(argc, argv, "--key", "key.pem");
  cfg->busy_poll   = (int)wired_cliargs_int(argc, argv, "--busy-poll", 0);
  cfg->port        = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  cfg->driver      = load_config_driver(argc, argv);
  if (cfg->driver == DRIVER_WORKERS) {
    cfg->workers.workers = (int)wired_cliargs_int(argc, argv, "--workers", 0);
    cfg->workers.pin_cores =
        (int)wired_cliargs_int(argc, argv, "--pin-cores", 0);
  }
  if (cfg->driver == DRIVER_XDP) load_config_xdp(cfg, argc, argv);
}

/* DRIVER_PLAIN: the plain single-process wired_server_run_opt path (identical
 * behavior to before the three drivers were unified). */
static int run_plain(
    const app_config* cfg, wired_srvboot_id* id, wired_srvrun_handler h) {
  wired_srvrun_obs obs = {
      cfg->qlog_path, cfg->keylog_path, cfg->cert_path, cfg->key_path, 0};
  wired_srvrun_opt opt = {cfg->busy_poll, 0, 0, 0, 0, 0, 0, 0, -1, 0};
  return wired_server_run_opt(cfg->port, id, h, obs, &opt);
}

/* DRIVER_WORKERS: fork N shared-nothing worker processes (tasks/core-pinning-
 * plan.md). wired_srvworkers_run does not return in normal operation; it
 * returns only negative, on the very first fork() failing. Normalized to
 * run_server's 1=ok/0=fail convention (matches wired_server_run_opt's). */
static int run_workers(
    const app_config* cfg, wired_srvboot_id* id, wired_srvrun_handler h) {
  wired_srvrun_obs obs = {0, 0, cfg->cert_path, cfg->key_path, 0};
  return wired_srvworkers_run(cfg->port, id, h, obs, &cfg->workers) >= 0;
}

/* DRIVER_XDP: open the AF_XDP socket/rings/BPF filter, then run the same
 * server loop with recv/send routed through it (tasks/xdp-driver-plan.md).
 * Prints the XDP_STATISTICS counters on exit. */
static int run_xdp(
    const app_config* cfg, wired_srvboot_id* id, wired_srvrun_handler h) {
  wired_srvxdp xdp = {0};
  int          ok;
  if (wired_srvxdp_open(&xdp, &cfg->xdp) < 0) die("AF_XDP open failed\n");
  {
    wired_srvrun_obs obs = {0, 0, cfg->cert_path, cfg->key_path, 0};
    wired_srvrun_opt opt = {0, 0, 0, 0, 0, 0, 0, 0, -1, &xdp};
    ok = wired_server_run_opt(cfg->port, id, h, obs, &opt);
  }
  wired_srvxdp_close(&xdp);
  return ok;
}

/* Dispatch to the driver selected by --workers/--ifindex; DRIVER_PLAIN
 * (neither given) is the default. */
static int run_server(
    const app_config* cfg, wired_srvboot_id* id, wired_srvrun_handler h) {
  if (cfg->driver == DRIVER_WORKERS) return run_workers(cfg, id, h);
  if (cfg->driver == DRIVER_XDP) return run_xdp(cfg, id, h);
  return run_plain(cfg, id, h);
}

/* The real entry point once argc/argv have been recovered from the kernel
 * stack by _start below. force_align_arg_pointer: the SysV ABI assumes a
 * return address was pushed (RSP%16==8) on entry, but _start's asm calls in
 * with RSP%16==0 (see _start); re-align so SSE moves in x25519/AEAD do not
 * fault. */
__attribute__((force_align_arg_pointer, used)) static int wired_main(
    int argc, char** argv) {
  wired_srvboot_id     id;
  server_keys          keys;
  app_config           cfg = {0};
  wired_srvrun_handler h   = {app_on_request, &cfg};
  app_selfcheck();
  load_config(&cfg, argc, argv);
  server_identity(&id, &keys);
  load_cert_files(&id, cfg.cert_path, cfg.key_path);
  if (!run_server(&cfg, &id, h)) die("listen failed\n");
  return 0;
}

/* Freestanding entry point. Linux x86_64 enters _start with the kernel-built
 * stack image: [argc][argv[0]]..[argv[argc-1]][NULL][envp...], RSP 16-byte
 * aligned at entry (no return address was pushed, unlike a normal call). This
 * reads argc into rdi and &argv[0] into rsi, then aligns down before calling
 * wired_main so the callee sees the SysV-expected RSP%16==8-after-call state.
 * naked: this function has no prologue/epilogue of its own, only the asm
 * below, since it is a real stack-frameless entry point, not a callable C
 * function. */
__attribute__((naked)) void _start(void) {
  asm volatile(
      "mov (%rsp), %rdi\n"
      "lea 8(%rsp), %rsi\n"
      "and $-16, %rsp\n"
      "call wired_main\n"
      "mov %eax, %edi\n"
      "mov $60, %eax\n" /* SYS_exit */
      "syscall\n");
}
