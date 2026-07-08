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

/* Fixed, deterministic server identity for wired_server_run_opt (same recipe
 * as webtransport_echo/word_list: a demo needs no key rotation). */
static const u8 SERVER_SCID[6] = {'W', 'T', 'C', 'H', 'A', 'T'};

typedef struct {
  u8 priv[32];
  u8 pub[32];
  u8 seed[32];
  u8 rnd[32];
} server_keys;

static void server_identity(wired_srvboot_id* id, server_keys* k) {
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
 * operator can pin/verify this server's identity out-of-band. */
static void log_cert_fingerprint(const u8 priv[32]) {
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
    quic_p256cert_key k = {priv, pub_x, pub_y};
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

/* CLI configuration: --port only (default 4433). */
static u16 load_config(int argc, char** argv) {
  return (u16)wired_cliargs_int(argc, argv, "--port", 4433);
}

__attribute__((force_align_arg_pointer, used)) static int wired_main(
    int argc, char** argv) {
  wired_srvboot_id     id;
  server_keys          keys;
  u16                  port = load_config(argc, argv);
  wired_srvrun_handler h    = {app_on_request, 0};
  wired_srvrun_opt     opt  = {0};

  server_identity(&id, &keys);
  log_cert_fingerprint(keys.priv);
  opt.incoming_cpu   = -1;
  opt.wt_on_datagram = wt_on_datagram_cb;
  {
    wired_srvrun_obs obs = {0, 0, 0, 0, 0};
    if (!wired_server_run_opt(port, &id, h, obs, &opt)) die("listen failed\n");
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
