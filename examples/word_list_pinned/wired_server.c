/* Real-UDP HTTP/3 server, multi-worker variant. libc-free, x86_64-linux,
 * direct syscalls, own _start, static.
 *
 * Identical application (message log / static file server) to
 * examples/word_list/wired_server.c -- the only difference is the entry
 * point: instead of a single wired_server_run, this calls
 * wired_srvworkers_run to fork N shared-nothing worker processes, each on
 * its own SO_REUSEPORT-shared socket, optionally pinned one-per-CPU-core.
 * See README.md for the demonstrated feature and its known limitation. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "wired.h"

#include "app/http3/server/srvworkers/srvworkers.h"

/* A fatal error: print and exit (freestanding, no libc atexit). */
static void die(const char* msg) {
  wired_log_str(msg);
  syscall1(SYS_exit, 1);
}

/* In-memory message store -- see examples/word_list for the rationale
 * (COW-shared at fork time, then independent per worker: each worker
 * process gets its own copy after fork, so history is per-worker, not
 * shared across the fleet; this is a demo, not a distributed log). */
#define HISTORY_MAX 8192
static u8  g_history[HISTORY_MAX];
static usz g_history_len;

static void history_append(const u8* body, usz n) {
  usz i;
  if (g_history_len < HISTORY_MAX) g_history[g_history_len++] = '\n';
  for (i = 0; i < n && g_history_len < HISTORY_MAX; i++)
    g_history[g_history_len++] = body[i];
}

static void copy_capped(quic_obuf* out, quic_span src) {
  usz i;
  for (i = 0; i < src.n && i < out->cap; i++) out->p[i] = src.p[i];
  out->len = i;
}

/* History-demo mode: RFC 9110 9.3.1 (GET) returns the log; 9.3.3 (POST)
 * appends and echoes. Always returns 200 (matches the wire :status). */
static u64 serve_history(const wired_h3reqdrive_req* req, quic_obuf* body_out) {
  if (req->method_len == 4 && req->method[0] == 'P') {
    history_append(req->body, req->body_len);
    copy_capped(body_out, quic_span_of(req->body, req->body_len));
    return 200;
  }
  copy_capped(body_out, quic_span_of(g_history, g_history_len));
  return 200;
}

static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    quic_obuf*                  body_out,
    const char**                content_type) {
  (void)ctx;
  (void)content_type;
  serve_history(req, body_out);
  return 1;
}

/* Fixed, deterministic server identity -- see examples/word_list for the
 * rationale (a demo needs no rotation). */
static const u8 SERVER_SCID[6] = {'C', 'L', 'I', 'S', 'C', 'I'};

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
  id->priv             = k->priv;
  id->pub              = k->pub;
  id->cert_seed        = k->seed;
  id->scid             = SERVER_SCID;
  id->scid_len         = sizeof SERVER_SCID;
  id->random           = k->rnd;
  id->chain            = 0; /* self-signed */
  id->chain_count      = 0;
  id->max_data         = 0;
  id->max_streams_bidi = 0;
}

/* Resolve CLI configuration: --port (default 4433), --workers (default 0 =
 * auto-detect CPU count), --pin-cores (default 0 = no affinity pinning). */
typedef struct {
  u16                   port;
  wired_srvworkers_opt  wopt;
} app_config;

static void load_config(app_config* cfg, int argc, char** argv) {
  cfg->port         = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  cfg->wopt.workers = (int)wired_cliargs_int(argc, argv, "--workers", 0);
  cfg->wopt.pin_cores =
      (int)wired_cliargs_int(argc, argv, "--pin-cores", 0);
}

__attribute__((force_align_arg_pointer, used)) static int wired_main(
    int argc, char** argv) {
  wired_srvboot_id     id;
  server_keys          keys;
  app_config           cfg;
  wired_srvrun_handler h = {app_on_request, 0};
  load_config(&cfg, argc, argv);
  server_identity(&id, &keys);
  {
    wired_srvrun_obs obs = {0, 0, 0, 0, 0};
    if (wired_srvworkers_run(cfg.port, &id, h, obs, &cfg.wopt) < 0)
      die("fork failed\n");
  }
  return 0;
}

/* Freestanding entry point -- identical layout to word_list/wired_server.c;
 * see that file's comment for the ABI-alignment rationale. */
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
