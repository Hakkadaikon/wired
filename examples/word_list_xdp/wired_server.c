/* AF_XDP-driven HTTP/3 server. libc-free, x86_64-linux, direct syscalls, own
 * _start, static. Driven by the single SDK header <wired.h>.
 *
 * Identical application (message log / static file server) to
 * examples/word_list/wired_server.c -- the only difference is the driver:
 * instead of the plain UDP recv/send path, this opens an AF_XDP socket
 * (wired_srvxdp_open) and routes wired_server_run_opt's receive/send through
 * it (wired_srvrun_opt.xdp), so packets are polled straight out of a shared
 * UMEM ring instead of one recvfrom(2)/sendto(2) syscall per datagram. See
 * README.md for the veth+netns root-only interop recipe and known limits. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "wired.h"

/* A fatal error: print and exit (freestanding, no libc atexit). */
static void die(const char* msg) {
  wired_log_str(msg);
  syscall1(SYS_exit, 1);
}

/* In-memory message store -- see examples/word_list for the rationale.
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

/* The request body is a scratch view, so this copies out. Always sends a
 * body. */
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

/* Self-check (ponytail: the only non-trivial app logic is the store/echo). */
static void app_selfcheck(void) {
  u8                   out[64];
  quic_obuf            ob           = {out, sizeof out, 0};
  const char*          content_type = 0;
  wired_h3reqdrive_req post         = {
      .method     = (const u8*)"POST",
      .method_len = 4,
      .body       = (const u8*)"hi",
      .body_len   = 2};
  wired_h3reqdrive_req get = {.method = (const u8*)"GET", .method_len = 3};
  g_history_len            = 0;
  app_on_request(0, &post, &ob, &content_type);
  if (ob.len != 2 || out[0] != 'h') die("selfcheck: echo failed\n");
  app_on_request(0, &get, &ob, &content_type);
  if (ob.len != 3 || out[1] != 'h' || out[2] != 'i')
    die("selfcheck: history failed\n");
  g_history_len = 0;
}

/* Fixed, deterministic server identity -- see examples/word_list for the
 * rationale (a demo needs no rotation). */
static const u8 SERVER_SCID[6] = {'C', 'L', 'I', 'S', 'C', 'I'};

/* The demo server's fixed key material buffers, owned by the caller (_start)
 * so they outlive wired_server_run_opt. */
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
  id->chain                   = 0; /* self-signed; see README.md */
  id->chain_count             = 0;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 65535;
  id->san_ipv4                = 0;
  id->now_secs                = 0;
}

/* Optional drop-in certificate: cert.pem (fullchain, leaf first, at most 2
 * certificates) and key.pem (P-256 private key), default paths overridable
 * via --cert/--key. Same loader as examples/word_list. */
static wired_certreload_store cert_store;

static void log_chain(usz n) {
  wired_log_str(n == 2 ? "cert.pem: 2 certs\n" : "cert.pem: 1 cert\n");
}

/* 1 if path opens and reads at least one byte (existence probe only).
 * WIRED_FIO_ETOOBIG counts as present too: it means the 1-byte probe buffer
 * filled and the file still had more data, i.e. the file exists and is
 * larger than a byte (every real cert/key is) -- rejecting it here made any
 * real cert.pem/key.pem look absent and silently fall back to self-signed. */
static int cert_file_present(const char* path) {
  u8  probe[1];
  ssz r = wired_fio_read(path, quic_mspan_of(probe, sizeof probe));
  return r >= 0 || r == WIRED_FIO_ETOOBIG;
}

/* Drop-in loader: neither cert_path nor key_path present keeps the
 * self-signed identity; a broken or half-present pair dies. */
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
 * cliargs_streq's while carries only one condition (see cliargs.c's
 * cli_char_match; kept local since examples are standalone TUs, not part of
 * the unity build). */
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

/* Application/driver configuration, resolved once at startup from argv. */
typedef struct {
  const char*      cert_path; /**< cert.pem path (--cert, default cert.pem) */
  const char*      key_path;  /**< key.pem path (--key, default key.pem) */
  wired_srvxdp_cfg xdp;       /**< --ifindex/--queue/--ip/--port/--skb-mode */
} app_config;

/* attach_flags: 0 = native XDP, 2 (XDP_FLAGS_SKB_MODE) = generic mode for
 * drivers/veth without native XDP support. */
static u32 attach_flags(int argc, char** argv) {
  if (cliargs_flag(argc, argv, "--skb-mode")) return 2u;
  return 0u;
}

/* --ifindex is required (no sensible default interface); a missing one is a
 * fatal config error. */
static void load_config_ifindex(wired_srvxdp_cfg* xdp, int argc, char** argv) {
  i64 ifindex = wired_cliargs_int(argc, argv, "--ifindex", -1);
  if (ifindex < 0) die("--ifindex is required\n");
  xdp->ifindex = (u32)ifindex;
}

/* --ip is required (no sensible default address); a missing/malformed one
 * is a fatal config error. */
static void load_config_ip(wired_srvxdp_cfg* xdp, int argc, char** argv) {
  if (!ipaddr_parse(wired_cliargs_str(argc, argv, "--ip", ""), xdp->ip))
    die("--ip a.b.c.d is required\n");
}

static void load_config(app_config* cfg, int argc, char** argv) {
  load_config_ifindex(&cfg->xdp, argc, argv);
  load_config_ip(&cfg->xdp, argc, argv);
  cfg->xdp.queue_id     = (u32)wired_cliargs_int(argc, argv, "--queue", 0);
  cfg->xdp.port         = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  cfg->xdp.bind_flags   = 0;
  cfg->xdp.attach_flags = attach_flags(argc, argv);
  cfg->cert_path        = wired_cliargs_str(argc, argv, "--cert", "cert.pem");
  cfg->key_path         = wired_cliargs_str(argc, argv, "--key", "key.pem");
}

/* Print the six XDP_STATISTICS counters (xsksetup.h order) as
 * "name value\n" lines. A stats read failure (e.g. socket already gone)
 * silently skips printing -- this runs at shutdown, after the run loop has
 * already returned, so there is nothing left to recover into. */
static const char* const STAT_NAMES[6] = {
    "rx_dropped",
    "rx_invalid_descs",
    "tx_invalid_descs",
    "rx_ring_full",
    "rx_fill_ring_empty_descs",
    "tx_ring_empty_descs",
};

static void print_stat_line(const char* name, u64 v) {
  char line[64];
  usz  at = 0;
  while (*name) line[at++] = *name++;
  line[at++] = ' ';
  wired_fmt_u64(line, &at, &(wired_fmt_u64_in){v, 1});
  line[at++] = '\n';
  line[at]   = 0;
  wired_log_str(line);
}

static void print_xdp_stats(i64 fd) {
  u64 stats[6];
  if (quic_xsksetup_stats(fd, stats) < 0) return;
  for (usz i = 0; i < 6; i++) print_stat_line(STAT_NAMES[i], stats[i]);
}

/* The real entry point once argc/argv have been recovered from the kernel
 * stack by _start below. force_align_arg_pointer: see examples/word_list's
 * comment for the ABI-alignment rationale. */
__attribute__((force_align_arg_pointer, used)) static int wired_main(
    int argc, char** argv) {
  wired_srvboot_id     id;
  server_keys          keys;
  app_config           cfg;
  wired_srvxdp         xdp = {0};
  wired_srvrun_handler h   = {app_on_request, 0};
  app_selfcheck();
  load_config(&cfg, argc, argv);
  server_identity(&id, &keys);
  load_cert_files(&id, cfg.cert_path, cfg.key_path);
  if (wired_srvxdp_open(&xdp, &cfg.xdp) < 0) die("AF_XDP open failed\n");
  {
    wired_srvrun_obs obs = {0, 0, cfg.cert_path, cfg.key_path, 0};
    wired_srvrun_opt opt = {0, 0, 0, 0, 0, 0, 0, 0, -1, &xdp};
    if (!wired_server_run_opt(cfg.xdp.port, &id, h, obs, &opt))
      die("listen failed\n");
  }
  print_xdp_stats(xdp.xsk.fd);
  wired_srvxdp_close(&xdp);
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
