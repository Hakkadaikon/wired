/* moq-interop-runner relay endpoint (draft-ietf-moq-transport-18/19/22).
 * libc-free, x86_64-linux, driven by the single SDK header <wired.h>.
 *
 * A bare wired_moqt_ hub relay (app/moqt/run/moqtrun.h): every namespace is
 * accepted. One UDP port serves both MoQT transports (draft-ietf-moq-
 * transport-22 6.1.2 / -19 3.1.3 / -18 3.1.2): a client that offers ALPN h3
 * gets WebTransport, whose CONNECT negotiates one of "moqt-18"/"moqt-19"/
 * "moqt-22" (via wired_moqt_wt_protocols); a client that offers one of those
 * same ids as its TLS ALPN gets raw (native) QUIC, reported through
 * wired_moqt_on_session_raw. The client's ALPN preference order decides.
 * The hub's io table is the SDK's transport mux wired_moqraw_io
 * (app/moqt/qraw/moqrawio.h), which adds the WT stream signal only on WT.
 * --no-raw (debug) serves WebTransport only.
 * Single-process only: the hub keeps its peer table in this process. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "app/moqt/qraw/moqrawio.h"
#include "app/moqt/run/moqtrun.h"
#include "app/moqt/ver/moqver.h"
#include "wired.h"

static wired_moqt_hub g_hub;

/* Object cache for FETCH (draft-ietf-moq-transport-19 10.12.3). */
static u8 g_cache_arena[1u << 20];

static void on_step(void* ctx, u64 now_ms) {
  wired_moqt_tick((wired_moqt_hub*)ctx, now_ms);
}

/* Plain HTTP/3 requests get an empty 200. */
static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    wired_obuf*                 body_out,
    const char**                content_type,
    int*                        more,
    u64*                        total_size) {
  (void)ctx;
  (void)req;
  (void)offset;
  (void)more;
  (void)total_size;
  *content_type = "text/plain";
  body_out->len = 0;
  return 1;
}

/* Fixed demo identity; --cert/--key replace the self-signed certificate. */
static void server_identity(wired_srvboot_id* id, wired_srvboot_demo_keys* k) {
  wired_srvboot_demo(id, k, 0x50, "MOQIOP");
  id->max_datagram_frame_size = 65535;
  id->now_secs                = wired_clock_epoch_secs();
}

/* Routes every WebTransport and raw-QUIC session callback to the hub. */
static void hub_callbacks(wired_srvrun_opt* run) {
  run->wt_on_session           = wired_moqt_on_session;
  run->wt_session_ctx          = &g_hub;
  run->wt_on_stream_data       = wired_moqt_on_stream_data;
  run->wt_stream_data_ctx      = &g_hub;
  run->wt_on_datagram          = wired_moqt_on_datagram;
  run->wt_datagram_ctx         = &g_hub;
  run->wt_on_stream_reset      = wired_moqt_on_stream_reset;
  run->wt_stream_reset_ctx     = &g_hub;
  run->wt_on_session_close     = wired_moqt_on_session_close;
  run->wt_session_close_ctx    = &g_hub;
  run->wt_on_session_draining  = wired_moqt_on_session_draining;
  run->wt_session_draining_ctx = &g_hub;
  run->raw_on_session          = wired_moqt_on_session_raw;
  run->raw_session_ctx         = &g_hub;
  run->on_step                 = on_step;
  run->on_step_ctx             = &g_hub;
}

/* RFC 7301 3.2: the same static list doubles as the raw-QUIC ALPN set,
 * unless --no-raw keeps the server WebTransport-only. */
static void raw_alpns(
    wired_srvboot_id* id, const char* protocols, int argc, char** argv) {
  if (!wired_cliargs_flag(argc, argv, "--no-raw")) {
    id->raw_alpns = protocols;
  }
}

/* --qlog/--keylog observers and the --cert/--key PEM pair. */
static wired_srvrun_obs cli_obs(int argc, char** argv) {
  return (wired_srvrun_obs){
      wired_cliargs_str(argc, argv, "--qlog", 0),
      wired_cliargs_str(argc, argv, "--keylog", 0),
      wired_cliargs_str(argc, argv, "--cert", 0),
      wired_cliargs_str(argc, argv, "--key", 0), 0};
}

/* Driver flags, the offered MoQT versions, and the hub callbacks. */
static void run_setup(
    wired_srvdriver_opt* opt, wired_srvboot_id* id, int argc, char** argv) {
  static char wt_protocols[32];
  if (!wired_srvdriver_parse(argc, argv, opt)) {
    wired_die("bad CLI flags (single-process only)\n");
  }
  wired_moqt_wt_protocols(wt_protocols, sizeof wt_protocols);
  raw_alpns(id, wt_protocols, argc, argv);
  opt->run.incoming_cpu = -1;
  opt->run.wt_protocols = wt_protocols;
  hub_callbacks(&opt->run);
}

__attribute__((force_align_arg_pointer, used)) int wired_main(
    int argc, char** argv) {
  static wired_certreload_store cert_store;
  wired_srvboot_id              id = {0};
  wired_srvboot_demo_keys       keys;
  wired_srvdriver_opt           opt;
  wired_srvrun_handler          h   = {.cb = app_on_request};
  wired_srvrun_obs              obs = cli_obs(argc, argv);

  server_identity(&id, &keys);
  wired_certreload_load_or_selfsigned(
      obs.cert_path, obs.key_path, &cert_store, &id);
  wired_moqt_init(&g_hub, wired_moqraw_io());
  wired_moqt_cache_attach(&g_hub, g_cache_arena, sizeof g_cache_arena);
  run_setup(&opt, &id, argc, argv);

  if (!wired_srvdriver_run(&id, h, obs, &opt)) {
    wired_die("listen failed\n");
  }
  return 0;
}
