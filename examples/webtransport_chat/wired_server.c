/* Real-UDP HTTP/3 + WebTransport chat server. libc-free, x86_64-linux, direct
 * syscalls, own _start, static. Driven by the single SDK header <wired.h>,
 * same recipe as examples/webtransport_echo.
 *
 * The chat logic itself is one line: every received WebTransport DATAGRAM is
 * fanned out, unmodified, to every active WT session via the SDK's own
 * wired_server_broadcast_datagram (src/app/http3/server/srvrun/srvrun.h).
 * This example does not parse or interpret message contents. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "wired.h"

/* Pulled in directly (not part of wired.h's umbrella): the wall clock that
 * anchors the certificate validity window and the hash for the startup
 * fingerprint log line -- same precedent as webtransport_echo including
 * app/webtransport headers directly. */
#include "app/http3/server/srvpin/srvpin.h"
#include "app/http3/server/srvthreads/srvthreads.h"
#include "common/platform/clock/clock.h"
#include "crypto/symmetric/hash/hash/sha256.h"

/* A fatal error: print and exit (freestanding, no libc atexit). */
static void die(const char* msg) {
  wired_log_str(msg);
  syscall1(SYS_exit, 1);
}

/* --- WebTransport chat: fan received datagrams out to every session ------ */

/* draft-ietf-webtrans-http3-15 SS4: relay one received DATAGRAM to every
 * active WebTransport session, byte-for-byte, no interpretation. */
static void wt_on_datagram_cb(
    void* app_ctx, wired_wt_session* s, quic_span data) {
  (void)app_ctx;
  (void)s;
  wired_server_broadcast_datagram(data);
}

/* --- Plain HTTP/3 app: identical shape to examples/webtransport_echo ----- */

/* A GET to any path answers 200 with a short description of this demo. */
static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    quic_obuf*                  body_out,
    const char**                content_type) {
  static const u8 body[] =
      "webtransport_chat: connect via WebTransport and send DATAGRAMs.\n"
      "Every received datagram is broadcast, unmodified, to every other\n"
      "active WebTransport session on this server.\n";
  usz i;
  (void)ctx;
  (void)req;
  *content_type = "text/plain";
  for (i = 0; i < sizeof body - 1 && i < body_out->cap; i++)
    body_out->p[i] = body[i];
  body_out->len = i;
  return 1;
}

/* --- CLI: --san-ipv4 a.b.c.d ---------------------------------------------
 * RFC 5280 4.2.1.6: a browser validating a WebTransport connection to a bare
 * IP literal (draft-ietf-webtrans-http3-15 serverCertificateHashes pinning
 * still enforces hostname validation, RFC 9110 4.3.5) checks the
 * certificate's SAN for that literal -- the SDK's default self-signed cert
 * carries only dNSName=localhost, so connecting to an IP address without
 * this flag fails hostname validation even with a correctly pinned hash. */

static int is_digit(char c) { return c >= '0' && c <= '9'; }

/* Consume base-10 digits from s[*off..) into *v (as u32), advancing *off.
 * Returns the digit count consumed; *v is only meaningful if it overflowed
 * 255 (caller's job to check) or the count is 0 (no digits at all). */
static usz consume_digits(const char* s, usz* off, u32* v) {
  usz digits = 0;
  *v         = 0;
  while (is_digit(s[*off])) {
    *v = *v * 10 + (u32)(s[*off] - '0');
    digits++;
    (*off)++;
  }
  return digits;
}

/* One base-10 octet (0..255) parsed from s[*off..), stopping at '.' or end.
 * Returns 1 ok, 0 on empty/out-of-range/no digits consumed. */
static int parse_octet(const char* s, usz* off, u8* out) {
  u32 v;
  usz digits = consume_digits(s, off, &v);
  if (!digits || v > 255) return 0;
  *out = (u8)v;
  return 1;
}

/* The '.' separator after octet i (i < 3), or the closing NUL after octet 3.
 * Returns 1 and advances *off past a separator, 0 on a mismatch. */
static int parse_ipv4_sep(const char* s, usz* off, usz octet_index) {
  if (octet_index == 3) return s[*off] == 0;
  if (s[*off] != '.') return 0;
  (*off)++;
  return 1;
}

/* Parse octet i and the separator/terminator after it. Returns 1 ok, 0 on
 * malformed input at this position. */
static int parse_ipv4_field(const char* s, usz* off, usz i, u8* out) {
  if (!parse_octet(s, off, out)) return 0;
  return parse_ipv4_sep(s, off, i);
}

/* "a.b.c.d" -> ip[4] network-byte-order. Returns 1 ok, 0 on malformed input
 * (wrong octet count, out-of-range octet, or trailing garbage). */
static int parse_ipv4(const char* s, u8 ip[4]) {
  usz off = 0;
  for (usz i = 0; i < 4; i++)
    if (!parse_ipv4_field(s, &off, i, &ip[i])) return 0;
  return 1;
}

/* --- CLI: --cores a,b,c (+ --control-core N) -----------------------------
 * Thread-based worker fan-out (srvthreads.h): one CPU index per worker,
 * comma-separated, no libc strtok. */

/* One base-10 core index parsed from s[*off..), stopping at ',' or end.
 * Returns 1 ok, 0 on empty/no digits consumed (reuses consume_digits, no
 * upper-bound check -- a bad CPU index is caught by sched_setaffinity, same
 * as --pin-core). */
static int cores_parse_one(const char* s, usz* off, int* out) {
  u32 v;
  usz digits = consume_digits(s, off, &v);
  if (!digits) return 0;
  *out = (int)v;
  return 1;
}

/* 1 and advances *off past a ',' when one follows (more entries to parse);
 * 0 with *off left at the NUL when the list ends here. */
static int cores_parse_more(const char* s, usz* off) {
  if (s[*off] != ',') return 0;
  (*off)++;
  return 1;
}

/* Parse one entry (index n) into out[n] and advance *off past it. Returns 1
 * ok, 0 if n is already at cap or the entry itself is malformed. */
static int cores_parse_entry(
    const char* s, usz* off, int* out, int n, int cap) {
  if (n >= cap) return 0;
  return cores_parse_one(s, off, &out[n]);
}

/* n if the list ended right here (NUL), -1 if cores_parse_more said "no more"
 * but trailing garbage remains (e.g. a stray separator other than ','). */
static int cores_parse_done(const char* s, usz off, int n) {
  return s[off] == 0 ? n : -1;
}

/* "a,b,c" -> out[0..n), up to cap entries. Returns the count parsed, or -1 on
 * a malformed entry or more entries than cap. */
static int cores_parse(const char* s, int* out, int cap) {
  usz off = 0;
  int n   = 0;
  while (cores_parse_entry(s, &off, out, n, cap)) {
    n++;
    if (!cores_parse_more(s, &off)) return cores_parse_done(s, off, n);
  }
  return -1;
}

/* Fixed, deterministic server identity for wired_server_run_opt (same recipe
 * as webtransport_echo/word_list: a demo needs no key rotation). */
static const u8 SERVER_SCID[6] = {'W', 'T', 'C', 'H', 'A', 'T'};

typedef struct {
  u8 priv[32];
  u8 pub[32];
  u8 seed[32];
  u8 rnd[32];
  u8 san_ipv4[4];
} server_keys;

static void server_identity(
    wired_srvboot_id* id, server_keys* k, int have_san_ipv4, u64 now_secs) {
  for (usz i = 0; i < 32; i++) {
    k->priv[i] = (u8)(0x50 + i);
    k->seed[i] = (u8)(0x90 + i);
    k->rnd[i]  = (u8)(0xb0 + i);
  }
  quic_x25519_base(k->pub, k->priv);
  id->priv                    = k->priv;
  id->pub                     = k->pub;
  id->cert_seed               = k->seed;
  id->scid                    = SERVER_SCID;
  id->scid_len                = sizeof SERVER_SCID;
  id->random                  = k->rnd;
  id->chain                   = 0; /* self-signed */
  id->chain_count             = 0;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 65535; /* required for DATAGRAM delivery */
  id->san_ipv4                = have_san_ipv4 ? k->san_ipv4 : 0;
  id->now_secs                = now_secs;
}

/* --- Startup cert fingerprint log --------------------------------------- */

/* One nibble (0..15) to its lowercase hex ASCII digit. */
static char hex_nibble(u8 v) {
  return (char)(v < 10 ? '0' + v : 'a' + (v - 10));
}

/* digest[0..32) -> "xx:xx:...:xx" (32*2 hex digits + 31 colons) into out,
 * which must be at least 32*3 bytes. Returns the written length. */
static usz hex_fingerprint(const u8 digest[32], char* out) {
  usz n = 0;
  for (usz i = 0; i < 32; i++) {
    if (i != 0) out[n++] = ':';
    out[n++] = hex_nibble((u8)(digest[i] >> 4));
    out[n++] = hex_nibble((u8)(digest[i] & 0xf));
  }
  return n;
}

/* SHA-256 the exact certificate DER this identity serves (the cert the TLS
 * flight carries, built by a throwaway wired_server_init from the same id
 * srvboot boots every connection with) and log it as a colon-hex fingerprint
 * -- the value a browser pins via serverCertificateHashes. Hashing the real
 * build output instead of reconstructing the cert in parallel means the log
 * cannot drift from the wire: a parallel reconstruction eventually disagrees
 * on an input (signing key, SAN, validity anchor) and pins an unservable
 * hash. */
static void log_cert_fingerprint(const wired_srvboot_id* id) {
  static wired_server  s; /* throwaway, sized in KB: keep it off the stack */
  wired_server_init_in in = {id->priv,    id->pub,         id->cert_seed,
                             id->chain,   id->chain_count, id->san_ipv4,
                             id->now_secs};
  u8                   digest[32];
  char                 line[32 + 32 * 3 + 2];
  usz                  n = 0;

  wired_server_init(&s, &in);
  if (s.sdrv.cert_count == 0) die("cert build failed\n");
  quic_sha256(s.sdrv.certs[0].p, s.sdrv.certs[0].n, digest);

  {
    static const char prefix[] = "cert sha-256 fingerprint: ";
    for (; prefix[n] != 0; n++) line[n] = prefix[n];
  }
  n += hex_fingerprint(digest, line + n);
  line[n++] = '\n';
  line[n]   = 0;
  wired_log_str(line);
}

typedef struct {
  u16                  port;
  const char*          qlog_path;
  const char*          keylog_path;
  int                  pin_core;    /**< --pin-core: CPU to pin to, -1 = off */
  int                  use_xdp;     /**< --ifindex given: run over AF_XDP */
  wired_srvxdp_cfg     xdp;         /**< --ifindex/--queue/--ip/--skb-mode */
  int                  use_threads; /**< --cores given: thread-based fan-out */
  wired_srvthreads_opt threads; /**< --cores/--control-core, DRIVER_THREADS */
} app_config;

/* --pin-core N: pin the process to CPU N via sched_setaffinity before the
 * run loop, so the XDP spin never migrates off its cache-warm core. */
static void maybe_pin_core(int cpu) {
  if (cpu < 0) return;
  if (wired_srvpin_bind_self(cpu) < 0)
    die("--pin-core: pinning failed (bad CPU index?)\n");
}

/* Both chars nonzero and equal: the "still matching" predicate, so
 * cliargs_streq's while carries only one condition (same helper trio as
 * examples/word_list; the examples are separate binaries, no collision). */
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

/* attach_flags: 0 = native XDP, 2 (XDP_FLAGS_SKB_MODE) = generic mode for
 * drivers/veth without native XDP support. */
static void load_config_xdp_flags(app_config* cfg, int argc, char** argv) {
  cfg->xdp.queue_id     = (u32)wired_cliargs_int(argc, argv, "--queue", 0);
  cfg->xdp.port         = cfg->port;
  cfg->xdp.bind_flags   = 0;
  cfg->xdp.attach_flags = cliargs_flag(argc, argv, "--skb-mode") ? 2u : 0u;
}

/* --ifindex selects the AF_XDP driver (same flags as examples/word_list);
 * --ip is then required (no sensible default address). Must run after
 * cfg->port is set: the BPF filter is built for that port. */
static void load_config_xdp(app_config* cfg, int argc, char** argv) {
  i64 ifindex  = wired_cliargs_int(argc, argv, "--ifindex", -1);
  cfg->use_xdp = ifindex >= 0;
  if (!cfg->use_xdp) return;
  cfg->xdp.ifindex = (u32)ifindex;
  if (!parse_ipv4(wired_cliargs_str(argc, argv, "--ip", ""), cfg->xdp.ip))
    die("--ip a.b.c.d is required with --ifindex\n");
  load_config_xdp_flags(cfg, argc, argv);
}

/* threads.xdp: 0 in UDP + SO_REUSEPORT mode, or the already-populated
 * cfg->xdp when --ifindex was also given (AF_XDP multi-queue mode, worker i
 * serves queue i). Split out so load_config_threads has no bare ?: of its
 * own. */
static const wired_srvxdp_cfg* threads_xdp_cfg(const app_config* cfg) {
  if (cfg->use_xdp) return &cfg->xdp;
  return 0;
}

/* cores_str is already known non-0 (load_config_threads' guard); parses
 * --cores/--control-core and the fixed srvrun knobs into cfg->threads. */
static void load_config_threads_body(
    app_config* cfg, int argc, char** argv, const char* cores_str) {
  cfg->threads.n_cores =
      cores_parse(cores_str, cfg->threads.cores, WIRED_SRVTHREADS_MAX);
  if (cfg->threads.n_cores <= 0) die("--cores: malformed core list\n");
  cfg->threads.control_core =
      (int)wired_cliargs_int(argc, argv, "--control-core", -1);
  cfg->threads.run                = (wired_srvrun_opt){0};
  cfg->threads.run.incoming_cpu   = -1;
  cfg->threads.run.wt_on_datagram = wt_on_datagram_cb;
  cfg->threads.xdp                = threads_xdp_cfg(cfg);
}

/* --cores a,b,c (+ optional --control-core N): thread-based worker fan-out
 * (srvthreads.h) sharing one address space, replacing the plain single-
 * process path. Must run after load_config_xdp: with --ifindex also given,
 * threads.xdp points at the already-populated cfg->xdp so srvthreads runs
 * AF_XDP in multi-queue mode instead of UDP + SO_REUSEPORT. */
static void load_config_threads(app_config* cfg, int argc, char** argv) {
  const char* cores_str = wired_cliargs_str(argc, argv, "--cores", 0);
  cfg->use_threads      = cores_str != 0;
  if (!cfg->use_threads) return;
  load_config_threads_body(cfg, argc, argv, cores_str);
}

/* CLI configuration: --port (default 4433), --san-ipv4 (optional, adds an
 * IPv4 SAN entry to the self-signed cert; die()s on a malformed value rather
 * than silently booting without hostname validation working), --qlog/--keylog
 * (optional debug log paths, see wired_srvrun_obs), the optional AF_XDP
 * driver (--ifindex/--queue/--ip/--skb-mode, tasks/xdp-driver-plan.md), and
 * the optional thread-based fan-out (--cores/--control-core; composes with
 * --ifindex for AF_XDP multi-queue mode). */
static void load_config(
    app_config* cfg, int argc, char** argv, u8 san_ipv4[4], int* have_it) {
  const char* ip_str = wired_cliargs_str(argc, argv, "--san-ipv4", 0);
  *have_it           = ip_str != 0;
  if (ip_str && !parse_ipv4(ip_str, san_ipv4))
    die("--san-ipv4: expected dotted-quad a.b.c.d\n");
  cfg->port        = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  cfg->qlog_path   = wired_cliargs_str(argc, argv, "--qlog", 0);
  cfg->keylog_path = wired_cliargs_str(argc, argv, "--keylog", 0);
  cfg->pin_core    = (int)wired_cliargs_int(argc, argv, "--pin-core", -1);
  load_config_xdp(cfg, argc, argv);
  load_config_threads(cfg, argc, argv);
}

/* Run the same server loop over an AF_XDP socket (examples/word_list's
 * DRIVER_XDP, minus the stats dump -- word_list stays the diagnostic
 * reference). The SDK routes every send through its one TX seam,
 * WebTransport DATAGRAM broadcasts included, so the chat logic above is
 * driver-agnostic. */
static int run_xdp(
    const app_config*       cfg,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    const wired_srvrun_obs* obs,
    wired_srvrun_opt*       opt) {
  wired_srvxdp xdp = {0};
  int          ok;
  if (wired_srvxdp_open(&xdp, &cfg->xdp) < 0) die("AF_XDP open failed\n");
  opt->xdp = &xdp;
  ok       = wired_server_run_opt(cfg->port, id, h, *obs, opt);
  wired_srvxdp_close(&xdp);
  return ok;
}

/* --cores a,b,c: thread-based worker fan-out (srvthreads.h), sharing one
 * address space; the control thread pins itself per --control-core and joins
 * every worker on shutdown. Takes priority over --ifindex-only XDP mode
 * (composes with it instead, via cfg->threads.xdp set in
 * load_config_threads). */
static int run_threads(
    const app_config*       cfg,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    const wired_srvrun_obs* obs) {
  return wired_srvthreads_run(cfg->port, id, h, *obs, &cfg->threads);
}

/* Dispatch to the driver selected by --cores/--ifindex; --cores (thread fan-
 * out) takes priority since it composes with --ifindex itself (AF_XDP multi-
 * queue mode, cfg->threads.xdp). Neither given runs the plain single-process
 * path, matching wired_server_run_opt's own default. */
static int run_dispatch(
    const app_config*       cfg,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    const wired_srvrun_obs* obs,
    wired_srvrun_opt*       opt) {
  if (cfg->use_threads) return run_threads(cfg, id, h, obs);
  if (cfg->use_xdp) return run_xdp(cfg, id, h, obs, opt);
  return wired_server_run_opt(cfg->port, id, h, *obs, opt);
}

/* --pin-core pins the single OS process/thread wired_main runs in; it is
 * meaningless once --cores hands worker pinning to srvthreads (which has its
 * own per-worker cores[] plus --control-core), so it is skipped in that mode
 * rather than fighting srvthreads for the same CPU mask. */
static void maybe_pin_core_unless_threaded(const app_config* cfg) {
  if (cfg->use_threads) return;
  maybe_pin_core(cfg->pin_core);
}

__attribute__((force_align_arg_pointer, used)) static int wired_main(
    int argc, char** argv) {
  wired_srvboot_id id;
  server_keys      keys;
  app_config       cfg;
  int              have_san_ipv4;
  load_config(&cfg, argc, argv, keys.san_ipv4, &have_san_ipv4);
  wired_srvrun_handler h        = {app_on_request, 0};
  wired_srvrun_opt     opt      = {0};
  u64                  now_secs = quic_clock_epoch_secs();

  server_identity(&id, &keys, have_san_ipv4, now_secs);
  log_cert_fingerprint(&id);
  opt.incoming_cpu   = -1;
  opt.wt_on_datagram = wt_on_datagram_cb;
  maybe_pin_core_unless_threaded(&cfg);
  {
    wired_srvrun_obs obs = {cfg.qlog_path, cfg.keylog_path, 0, 0, 0};
    if (!run_dispatch(&cfg, &id, h, &obs, &opt)) die("listen failed\n");
  }
  return 0;
}

/* Freestanding entry point; identical recipe to examples/webtransport_echo. */
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
