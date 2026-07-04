/* Real-UDP HTTP/3 server. libc-free, x86_64-linux, direct syscalls, own _start,
 * static. Driven by the single SDK header <wired.h>.
 *
 * The whole server — bind, receive, cold-start each client Initial, drive the
 * handshake, answer HTTP/3 requests, seal every reply — is wired_server_run.
 * This file is just the application: a message log (POST appends and echoes,
 * GET returns the whole log) or, with --root, a static file server; the demo
 * server identity; CLI configuration; and the freestanding entry point. See
 * examples/README.md for what completes here vs. what an external HTTP/3
 * client additionally needs. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "wired.h"

/* A fatal error: print and exit (freestanding, no libc atexit). */
static void die(const char *msg) {
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
static void history_append(const u8 *body, usz n) {
  usz i;
  if (g_history_len < HISTORY_MAX) g_history[g_history_len++] = '\n';
  for (i = 0; i < n && g_history_len < HISTORY_MAX; i++)
    g_history[g_history_len++] = body[i];
}

/* Copy up to out->cap bytes of src into out, setting out->len to the count
 * copied. */
static void copy_capped(quic_obuf *out, quic_span src) {
  usz i;
  for (i = 0; i < src.n && i < out->cap; i++) out->p[i] = src.p[i];
  out->len = i;
}

/* Application configuration, resolved once at startup from argv and handed
 * to app_on_request as its opaque ctx. --root selects static file mode;
 * absent, the demo history mode runs unchanged (back-compat). */
typedef struct {
  const char *root;         /**< document root, or 0 for history-demo mode */
  const char *index;        /**< index file name for directory requests */
  const char *access_log;   /**< access log path, or 0 to disable logging */
} app_config;

/* One line per request: "METHOD PATH STATUS BYTES\n" (ponytail: fixed
 * single-line format, no log levels/rotation — add if an operator needs it).
 */
static void access_log(
    const app_config *cfg, quic_span method, quic_span path, u64 status,
    u64 nbytes) {
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
  wired_fio_append(cfg->access_log, quic_span_of((const u8 *)line, at));
}

/* Write the 404 body and return its status code. */
static u64 not_found(quic_obuf *body_out) {
  copy_capped(body_out, quic_span_of((const u8 *)"404 Not Found\n", 14));
  return 404;
}

/* Static-file mode (quiche-server's --root/--index): resolve the request path
 * under cfg->root and serve the file's bytes, or a 404 body when it does not
 * resolve/open (the wire :status stays 200 — see srvloop/respond.c, which
 * hard-codes 200 for every decoded request; changing that is a larger,
 * separate change). The logged status reflects whether the file was found. */
static u64 serve_static(
    const app_config *cfg, quic_span path, quic_obuf *body_out,
    const char **content_type) {
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
  *content_type  = wired_mimetype_for_path(resolved);
  return 200;
}

/* History-demo mode (--root absent): RFC 9110 9.3.1 (GET) returns the log;
 * 9.3.3 (POST) appends and echoes. Always returns 200 (matches the wire
 * :status, which srvloop always sends as 200). */
static u64 serve_history(const wired_h3reqdrive_req *req, quic_obuf *body_out) {
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
    void *ctx, const wired_h3reqdrive_req *req, quic_obuf *body_out,
    const char **content_type) {
  const app_config *cfg    = (const app_config *)ctx;
  quic_span          method = quic_span_of(req->method, req->method_len);
  quic_span          path   = quic_span_of(req->path, req->path_len);
  u64                status = cfg->root
                                   ? serve_static(cfg, path, body_out, content_type)
                                   : serve_history(req, body_out);
  access_log(cfg, method, path, status, body_out->len);
  return 1;
}

/* Self-check (ponytail: the only non-trivial app logic is the store/echo). */
static void app_selfcheck(void) {
  u8                   out[64];
  quic_obuf            ob          = {out, sizeof out, 0};
  app_config           cfg         = {0, 0, 0};
  const char          *content_type = 0;
  wired_h3reqdrive_req post = {(const u8 *)"POST", 4, 0, 0, 0, 0, 0, 0,
                               (const u8 *)"hi",   2};
  wired_h3reqdrive_req get  = {(const u8 *)"GET", 3, 0, 0, 0, 0, 0, 0, 0, 0};
  g_history_len             = 0;
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

static void server_identity(wired_srvboot_id *id, server_keys *k) {
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
}

/* Optional drop-in certificate: cert.pem (fullchain, leaf first, at most 2
 * certificates) and key.pem (P-256 private key) read from the cwd at startup.
 * Static storage because the identity holds views into it for the whole run.
 * ponytail: 8 KiB cert / 4 KiB key caps — grow the arrays if a chain outgrows
 * them. */
static u8        cert_pem[8192], key_pem[4096], chain_der[8192];
static quic_span chain[2];
static u8        leaf_priv[32];

/* Decode up to 2 CERTIFICATE blocks (RFC 7468 5) from a fullchain PEM. */
static int next_cert(quic_span text, usz *at, quic_obuf *der, usz n) {
  quic_span label;
  return n < 2 && wired_pem_next(text, at, &label, der);
}

/* Fill chain[] from the PEM text, leaf first; die if no block decodes. */
static usz load_pem_chain(quic_span text) {
  quic_obuf der = quic_obuf_of(chain_der, sizeof chain_der);
  usz       at = 0, n = 0, start = 0;
  while (next_cert(text, &at, &der, n)) {
    chain[n++] = quic_span_of(chain_der + start, der.len - start);
    start      = der.len;
  }
  if (n == 0) die("bad cert.pem/key.pem\n");
  return n;
}

/* Extract the P-256 private scalar from key.pem's first block (EC PRIVATE
 * KEY or PKCS#8 PRIVATE KEY; wired_eckey_p256_priv validates the DER). */
static void load_key_priv(quic_span text) {
  u8        der_buf[192];
  quic_obuf der = quic_obuf_of(der_buf, sizeof der_buf);
  quic_span label;
  usz       at = 0;
  if (!wired_pem_next(text, &at, &label, &der)) die("bad cert.pem/key.pem\n");
  if (!wired_eckey_p256_priv(quic_span_of(der_buf, der.len), leaf_priv))
    die("bad cert.pem/key.pem\n");
}

static void log_chain(usz n) {
  wired_log_str(n == 2 ? "cert.pem: 2 certs\n" : "cert.pem: 1 cert\n");
}

/* Point the identity at the loaded chain and its signing scalar. */
static void install_cert(wired_srvboot_id *id, ssz cn, ssz kn) {
  if (cn < 0 || kn < 0) die("bad cert.pem/key.pem\n");
  id->chain_count = load_pem_chain(quic_span_of(cert_pem, (usz)cn));
  load_key_priv(quic_span_of(key_pem, (usz)kn));
  id->cert_seed = leaf_priv;
  id->chain     = chain;
  log_chain(id->chain_count);
}

/* Drop-in loader: both files absent keeps the self-signed identity; a broken
 * or half-present pair dies rather than silently serving self-signed. */
static void load_cert_files(wired_srvboot_id *id) {
  ssz cn = wired_fio_read("cert.pem", quic_mspan_of(cert_pem, sizeof cert_pem));
  ssz kn = wired_fio_read("key.pem", quic_mspan_of(key_pem, sizeof key_pem));
  if (cn < 0 && kn < 0) {
    wired_log_str("self-signed (no cert.pem)\n");
    return;
  }
  install_cert(id, cn, kn);
}

/* Resolve CLI configuration: --port (default 4433), --root (static file mode,
 * absent = history demo), --index (default index.html), --access-log
 * (absent = no logging). */
static u16 load_config(app_config *cfg, int argc, char **argv) {
  cfg->root       = wired_cliargs_str(argc, argv, "--root", 0);
  cfg->index      = wired_cliargs_str(argc, argv, "--index", "index.html");
  cfg->access_log = wired_cliargs_str(argc, argv, "--access-log", 0);
  return (u16)wired_cliargs_int(argc, argv, "--port", 4433);
}

/* The real entry point once argc/argv have been recovered from the kernel
 * stack by _start below. force_align_arg_pointer: the SysV ABI assumes a
 * return address was pushed (RSP%16==8) on entry, but _start's asm calls in
 * with RSP%16==0 (see _start); re-align so SSE moves in x25519/AEAD do not
 * fault. */
__attribute__((force_align_arg_pointer, used)) static int wired_main(
    int argc, char **argv) {
  wired_srvboot_id     id;
  server_keys          keys;
  app_config           cfg;
  u16                  port = load_config(&cfg, argc, argv);
  wired_srvrun_handler h    = {app_on_request, &cfg};
  app_selfcheck();
  server_identity(&id, &keys);
  load_cert_files(&id);
  if (!wired_server_run(port, &id, h)) die("listen failed\n");
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
