/* Real-UDP HTTP/3 server, plus a WebTransport building-blocks self-test.
 * libc-free, x86_64-linux, direct syscalls, static. Driven by the single SDK
 * header <wired.h> (WIRED_MAIN supplies _start), same as examples/word_list.
 *
 * HONEST SCOPE (see README.md for the full explanation): this binary serves
 * plain HTTP/3 requests exactly like word_list. It does NOT serve real,
 * interactive WebTransport sessions over the wire -- srvloop/dispatch do not
 * yet route Extended CONNECT into a wired_wt_session or associate uni/bidi
 * streams or DATAGRAM frames with one (grep confirms zero call sites). What
 * IS real: the WebTransport session state machine (wired_wt_session_*), the
 * WT_CLOSE_SESSION/WT_DRAIN_SESSION capsule codec (quic_wtcapsule_*), and the
 * WT<->HTTP/3 error-code mapping (quic_wterrmap_*) are implemented and
 * independently tested components. This example drives them directly, once,
 * at startup, and logs each step to stdout, so a reader can see the pieces
 * that exist and how they'd compose once the receive-side wiring lands. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "wired.h"

/* WebTransport building blocks: not part of the wired.h umbrella yet (no
 * receive path wires them), so pulled in directly for the self-test only. */
#include "app/webtransport/capsule/wtcapsule/wtcapsule.h"
#include "app/webtransport/errmap/errmap/errmap.h"
#include "app/webtransport/session/session/session.h"
#include "common/platform/exit/exit.h"

/* --- WebTransport building-blocks self-test (startup only, logged) ------- */

/* wired_die with msg unless ok. */
static void wt_selfcheck_require(int ok, const char* msg) {
  if (!ok) wired_die(msg);
}

/* Pre-establishment: a stream and a datagram are buffered while
 * unestablished. */
static void wt_selfcheck_session_buffer(wired_wt_session* s) {
  wt_selfcheck_require(
      s->state == WIRED_WT_UNESTABLISHED, "wt: bad init state\n");
  wt_selfcheck_require(
      wired_wt_session_offer_stream(s, /*stream_id=*/4),
      "wt: buffer stream failed\n");
  wt_selfcheck_require(
      wired_wt_session_offer_datagram(s, quic_span_of((const u8*)"hi", 2)),
      "wt: buffer datagram failed\n");
}

/* Establish, then a post-establishment stream is associated directly. */
static void wt_selfcheck_session_establish(wired_wt_session* s) {
  wt_selfcheck_require(
      wired_wt_session_establish(s), "wt: establish failed\n");
  wt_selfcheck_require(
      s->state == WIRED_WT_ESTABLISHED, "wt: not established\n");
  wt_selfcheck_require(
      wired_wt_session_offer_stream(s, /*stream_id=*/8),
      "wt: post-establish stream offer failed\n");
}

static void wt_selfcheck_session_close(wired_wt_session* s) {
  if (!wired_wt_session_close(s)) wired_die("wt: close failed\n");
  if (s->state != WIRED_WT_CLOSED) wired_die("wt: not closed\n");
}

/* Session state machine: unestablished -> a pre-establishment stream/datagram
 * is buffered -> establish -> both are considered associated -> close.
 * Mirrors wired_wt_session's own documented lifecycle (session.h). */
static void wt_selfcheck_session(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, /*connect_stream_id=*/0);
  wt_selfcheck_session_buffer(&s);
  wt_selfcheck_session_establish(&s);
  wt_selfcheck_session_close(&s);
  wired_log_str(
      "wt-selfcheck: session unestablished->established->closed ok\n");
}

/* Encode then decode a WT_CLOSE_SESSION capsule, checking both steps
 * succeed. Returns the decoded fields via code_out and msg_out. */
static void wt_selfcheck_capsule_roundtrip(
    u32 code, quic_span msg, u32* code_out, quic_span* msg_out) {
  u8        buf[64];
  quic_obuf ob = {buf, sizeof buf, 0};
  usz       at = 0;
  if (!quic_wtcapsule_encode_close(&ob, code, msg))
    wired_die("wt: capsule encode failed\n");
  if (!quic_wtcapsule_decode_close(
          quic_span_of(buf, ob.len), &at, code_out, msg_out))
    wired_die("wt: capsule decode failed\n");
}

/* WT_CLOSE_SESSION capsule: encode then decode round-trips the error code and
 * message, built on the existing generic RFC 9297 Capsule Protocol codec. */
static void wt_selfcheck_capsule(void) {
  const u8  msg[] = {'b', 'y', 'e'};
  u32       code_out;
  quic_span msg_out;
  wt_selfcheck_capsule_roundtrip(
      0x2a, quic_span_of(msg, sizeof msg), &code_out, &msg_out);
  if (code_out != 0x2a || msg_out.n != sizeof msg)
    wired_die("wt: capsule round-trip mismatch\n");
  wired_log_str("wt-selfcheck: WT_CLOSE_SESSION capsule round-trip ok\n");
}

/* WT<->HTTP/3 error-code mapping: forward then reverse recovers the original
 * application error code (draft-ietf-webtrans-http3-15 8.2). */
static void wt_selfcheck_errmap(void) {
  u32 n = 0x2a;
  u64 h = quic_wterrmap_to_http3(n);
  u32 n_out;

  if (!quic_wterrmap_from_http3(h, &n_out) || n_out != n)
    wired_die("wt: errmap round-trip mismatch\n");

  wired_log_str("wt-selfcheck: error-code mapping round-trip ok\n");
}

static void wt_selfcheck(void) {
  wt_selfcheck_session();
  wt_selfcheck_capsule();
  wt_selfcheck_errmap();
}

/* --- Plain HTTP/3 app: identical shape to examples/word_list ------------- */

/* A GET to any path answers 200 with a short body explaining what this demo
 * is (see README.md for the honest scope). No POST/echo store here -- that
 * is word_list's demo, not this one's. */
static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    quic_obuf*                  body_out,
    const char**                content_type) {
  static const u8 body[] =
      "webtransport_echo: plain HTTP/3 only over the wire.\n"
      "WebTransport session/capsule/errmap building blocks are exercised\n"
      "at startup (see stdout), not yet routed from real WT wire traffic.\n";
  usz i;
  (void)ctx;
  (void)req;
  *content_type = "text/plain";
  for (i = 0; i < sizeof body - 1 && i < body_out->cap; i++)
    body_out->p[i] = body[i];
  body_out->len = i;
  return 1;
}

/* Fixed, deterministic server identity for wired_server_run (same recipe as
 * word_list: a demo needs no key rotation). */
static const u8 SERVER_SCID[6] = {'W', 'T', 'E', 'C', 'H', 'O'};

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
  id->priv      = k->priv;
  id->pub       = k->pub;
  id->cert_seed = k->seed;
  id->scid      = SERVER_SCID;
  id->scid_len  = sizeof SERVER_SCID;
  id->random    = k->rnd;
  id->chain     = 0; /* self-signed; see word_list's README for a
                         real-CA chain drop-in, same recipe applies */
  id->chain_count             = 0;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 65535;
  id->san_ipv4                = 0;
  id->now_secs                = 0;
}

/* CLI configuration: --port only (default 4433). No --root/--cert/--key
 * knobs here -- this example's only purpose is the WT building-blocks demo
 * plus a minimal HTTP/3 responder; see word_list for the fuller CLI surface.
 */
static u16 load_config(int argc, char** argv) {
  return (u16)wired_cliargs_int(argc, argv, "--port", 4433);
}

__attribute__((force_align_arg_pointer)) int wired_main(
    int argc, char** argv) {
  wired_srvboot_id     id;
  server_keys          keys;
  u16                  port = load_config(argc, argv);
  wired_srvrun_handler h    = {app_on_request, 0};

  wt_selfcheck();
  server_identity(&id, &keys);
  {
    wired_srvrun_obs obs = {0, 0, 0, 0, 0};
    if (!wired_server_run(port, &id, h, obs)) wired_die("listen failed\n");
  }
  return 0;
}
