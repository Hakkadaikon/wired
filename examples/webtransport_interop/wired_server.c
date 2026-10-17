/* quic-interop-runner WebTransport server endpoint. libc-free, x86_64-linux,
 * direct syscalls, driven by the single SDK header <wired.h>.
 *
 * The runner (webtransport.md) sets TESTCASE / PROTOCOLS / REQUESTS in the
 * environment and mounts /www (files to serve), /downloads (files to save)
 * and /certs (cert.pem + priv.key). Supported test cases:
 *
 * - handshake: on session establishment, write the negotiated subprotocol
 *   to /downloads/negotiated_protocol.txt and keep serving.
 * - transfer: passive. "GET <file>" on a client uni stream is answered with
 *   "PUSH <basename>\n" + content on a NEW uni stream; on a client bidi
 *   stream with the bare content on the SAME stream; in a datagram with a
 *   "PUSH <basename>\n" + content datagram. A missing file is ignored.
 * - transfer-{unidirectional,bidirectional,datagram}-send: active. Once a
 *   session for the REQUESTS endpoint is established, every listed file is
 *   requested with "GET <file>" (new uni stream / new bidi stream / one
 *   datagram per file) and the client's replies are saved under
 *   /downloads/<endpoint>/<basename>. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim and _start */
#include "wt_interop.h"

/* --- test-case modes ----------------------------------------------------- */

typedef struct {
  const char* name;
  int         mode;
} mode_row;

static const mode_row MODES[] = {
    {"handshake", MODE_HANDSHAKE},
    {"transfer", MODE_TRANSFER},
    {"transfer-unidirectional-send", MODE_UNI_SEND},
    {"transfer-bidirectional-send", MODE_BIDI_SEND},
    {"transfer-datagram-send", MODE_DG_SEND},
};

int wti_mode;

/* --- session establishment ----------------------------------------------- */

static void on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  (void)ctx;
  wti_session_note(s, path);
  if (wti_mode == MODE_HANDSHAKE) {
    wired_fio_write_new("/downloads/negotiated_protocol.txt", protocol);
  }
  wti_send_gets(s, path);
}

/* --- datagrams ------------------------------------------------------------ */

static void dg_handle(wired_wt_session* s, wired_span msg) {
  if (wti_mode == MODE_TRANSFER) {
    wti_dg_serve(s, msg);
  }
  if (wti_mode == MODE_DG_SEND) {
    wti_dg_save(s, msg);
  }
}

/* The SDK strips the RFC 9297 2.1 quarter-stream-id prefix and resolves the
 * session before this fires (that is how `s` is known), so dg already starts
 * at the application bytes -- taking another varint here would eat the first
 * payload byte ('G' of GET / 'P' of PUSH) and fail every parse. */
static void on_datagram(void* ctx, wired_wt_session* s, wired_span dg) {
  (void)ctx;
  dg_handle(s, dg);
}

/* --- plain HTTP/3 app (the runner only health-checks it) ----------------- */

static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    wired_obuf*                 body_out,
    const char**                content_type,
    int*                        more,
    u64*                        total_size) {
  static const u8 body[] =
      "webtransport_interop: quic-interop-runner WebTransport endpoint.\n";
  usz i;
  (void)ctx;
  (void)req;
  (void)offset;
  (void)more;
  (void)total_size;
  *content_type = "text/plain";
  for (i = 0; i < sizeof body - 1 && i < body_out->cap; i++) {
    body_out->p[i] = body[i];
  }
  body_out->len = i;
  return 1;
}

/* --- server identity + startup ------------------------------------------- */

static void server_identity(wired_srvboot_id* id, wired_srvboot_demo_keys* k) {
  wired_srvboot_demo(id, k, 0x60, "WTINOP");
  id->max_datagram_frame_size = 65535; /* required for DATAGRAM delivery */
}

/* The certificate store backs id's views for the whole run. */
static wired_certreload_store cert_store;

static int mode_lookup(const char* tc) {
  for (usz i = 0; i < sizeof MODES / sizeof MODES[0]; i++) {
    if (wired_span_eq_cstr(wired_span_cstr(tc), MODES[i].name)) {
      return MODES[i].mode;
    }
  }
  return -1;
}

/* TESTCASE -> mode, or -1 when unset/unsupported. */
static int mode_of(const char* tc) { return tc ? mode_lookup(tc) : -1; }

/* --qlog-file/--keylog-file observers and the --cert/--key pair. */
static wired_srvrun_obs cli_obs(int argc, char** argv) {
  return (wired_srvrun_obs){
      wired_cliargs_str(argc, argv, "--qlog-file", 0),
      wired_cliargs_str(argc, argv, "--keylog-file", 0),
      wired_cliargs_str(argc, argv, "--cert", 0),
      wired_cliargs_str(argc, argv, "--key", "key.pem"), 0};
}

/* The WebTransport callbacks and the runner's PROTOCOLS list. */
static void run_opts(wired_srvrun_opt* opt, int argc, char** argv) {
  opt->incoming_cpu      = -1;
  opt->wt_on_datagram    = on_datagram;
  opt->wt_on_stream_data = wti_on_stream_data;
  opt->wt_on_session     = on_session;
  opt->wt_protocols      = wired_envp_get(argc, argv, "PROTOCOLS");
}

__attribute__((force_align_arg_pointer)) int wired_main(int argc, char** argv) {
  wired_srvboot_id        id = {0};
  wired_srvboot_demo_keys keys;
  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 443);
  wired_srvrun_handler h    = {.cb = app_on_request};
  wired_srvrun_opt     opt  = {0};
  wired_srvrun_obs     obs  = cli_obs(argc, argv);

  wti_mode = mode_of(wired_envp_get(argc, argv, "TESTCASE"));
  if (wti_mode < 0) {
    wired_log_str("unsupported TESTCASE\n");
    return 127; /* the interop-runner code for "not supported" */
  }
  wti_requests_parse(wired_envp_get(argc, argv, "REQUESTS"));
  wti_prep_get_lines();
  wti_setup_downloads();

  server_identity(&id, &keys);
  wired_certreload_load_or_selfsigned(
      obs.cert_path, obs.key_path, &cert_store, &id);
  run_opts(&opt, argc, argv);

  if (!wired_server_run_opt(port, &id, h, obs, &opt)) {
    wired_die("listen failed\n");
  }
  return 0;
}
