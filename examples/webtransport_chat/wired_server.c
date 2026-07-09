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

/* Certificate-build internals, pulled in directly (not part of wired.h's
 * umbrella) to compute the startup fingerprint log line -- same precedent as
 * webtransport_echo including app/webtransport headers directly. */
#include "crypto/asymmetric/ecc/p256/p256_field.h"
#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/pki/cert/p256cert/p256cert.h"
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
    wired_srvboot_id* id, server_keys* k, int have_san_ipv4) {
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

/* RFC 5480 / RFC 5280 4.1: rebuild the same self-signed cert sdrv would (see
 * sdrv_build_cert), then SHA-256 the DER and log it as a fingerprint so an
 * operator can pin/verify this server's identity out-of-band. san_ipv4 (0 to
 * omit) mirrors server_identity's own choice, so the logged fingerprint
 * always matches what the server actually sends. */
static void log_cert_fingerprint(const u8 priv[32], const u8* san_ipv4) {
  ec_point q;
  u8       pub_x[32], pub_y[32];
  u8       cert_buf[1024];
  u8       digest[32];
  char     line[16 + 32 * 3 + 2];
  usz      n = 0;

  quic_ec_mul(&q, priv, &quic_p256_g);
  quic_fp_to_be(pub_x, q.x);
  quic_fp_to_be(pub_y, q.y);
  {
    quic_p256cert_key k = {priv, pub_x, pub_y, san_ipv4};
    quic_obuf         o = quic_obuf_of(cert_buf, sizeof cert_buf);
    quic_p256cert_build(&k, &o);
    quic_sha256(cert_buf, o.len, digest);
  }

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
  u16         port;
  const char* qlog_path;
  const char* keylog_path;
} app_config;

/* CLI configuration: --port (default 4433), --san-ipv4 (optional, adds an
 * IPv4 SAN entry to the self-signed cert; die()s on a malformed value rather
 * than silently booting without hostname validation working), --qlog/--keylog
 * (optional debug log paths, see wired_srvrun_obs). */
static void load_config(
    app_config* cfg, int argc, char** argv, u8 san_ipv4[4], int* have_it) {
  const char* ip_str = wired_cliargs_str(argc, argv, "--san-ipv4", 0);
  *have_it            = ip_str != 0;
  if (ip_str && !parse_ipv4(ip_str, san_ipv4))
    die("--san-ipv4: expected dotted-quad a.b.c.d\n");
  cfg->port        = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  cfg->qlog_path   = wired_cliargs_str(argc, argv, "--qlog", 0);
  cfg->keylog_path = wired_cliargs_str(argc, argv, "--keylog", 0);
}

__attribute__((force_align_arg_pointer, used)) static int wired_main(
    int argc, char** argv) {
  wired_srvboot_id id;
  server_keys      keys;
  app_config       cfg;
  int              have_san_ipv4;
  load_config(&cfg, argc, argv, keys.san_ipv4, &have_san_ipv4);
  wired_srvrun_handler h   = {app_on_request, 0};
  wired_srvrun_opt     opt = {0};

  server_identity(&id, &keys, have_san_ipv4);
  log_cert_fingerprint(keys.priv, id.san_ipv4);
  opt.incoming_cpu   = -1;
  opt.wt_on_datagram = wt_on_datagram_cb;
  {
    wired_srvrun_obs obs = {cfg.qlog_path, cfg.keylog_path, 0, 0, 0};
    if (!wired_server_run_opt(cfg.port, &id, h, obs, &opt))
      die("listen failed\n");
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
