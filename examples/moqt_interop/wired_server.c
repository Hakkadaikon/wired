/* moq-interop-runner relay endpoint (draft-ietf-moq-transport-18/19/22).
 * libc-free, x86_64-linux, driven by the single SDK header <wired.h>.
 *
 * A bare wired_moqt_ hub relay (app/moqt/run/moqtrun.h): every namespace is
 * accepted, the WebTransport CONNECT negotiates one of "moqt-18"/"moqt-19"/
 * "moqt-22" (whichever the client offers, via wired_moqt_wt_protocols), and
 * this file only adapts wired_server_wt_* into the hub's wired_moqt_io
 * table (signal prefix on the stream-opening entries, see
 * examples/moqt_chat/wired_server.c for the full rationale).
 * Single-process only: the hub keeps its peer table in this process. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "app/moqt/run/moqtrun.h"
#include "app/moqt/ver/moqver.h"
#include "app/webtransport/wtwire/wtwire.h"
#include "wired.h"

/* Signal prefix + one relay round; the SDK copies the payload during the
 * call (srvrun.h), so one static buffer serves every open. */
static u8 g_open_buf[65536];

typedef i64 (*wt_open_fn)(wired_wt_session* s, wired_span payload);

/* Prefixes the WebTransport stream signal (draft-ietf-webtrans-http3-15
 * 4.2) and hands the stream to open. */
static i64 open_signalled(
    wt_open_fn open, wired_wt_session* s, wired_span payload) {
  usz sig = wired_wtwire_signal_put(
      g_open_buf, sizeof g_open_buf, 0, s->connect_stream_id);
  if (sig == 0 || payload.n > sizeof g_open_buf - sig) return -1;
  bytes_memcpy(g_open_buf + sig, payload.p, payload.n);
  return open(s, wired_span_of(g_open_buf, sig + payload.n));
}

static i64 io_send_uni(wired_wt_session* s, wired_span p) {
  return open_signalled(wired_server_wt_open_uni, s, p);
}

static i64 io_open_uni_stream(wired_wt_session* s, wired_span p) {
  return open_signalled(wired_server_wt_open_uni_stream, s, p);
}

/* Remaining WT_MAX_DATA credit; a peer that never sent one has no limit. */
static usz io_send_budget(wired_wt_session* s) {
  if (s->max_data == 0) return (usz)-1;
  return s->max_data > s->sent_data ? s->max_data - s->sent_data : 0;
}

static i64 io_open_bidi_stream(wired_wt_session* s, wired_span p) {
  return open_signalled(wired_server_wt_open_bidi_stream, s, p);
}

/* Sessions negotiating a moqt-NN subprotocol get the draft-19 3.3 uni
 * control-stream pair from the hub itself; the bidi entry only serves a
 * session without a token. send_uni2 is 0: it serves only
 * wired_moqt_publish_live, unused here. */
static const wired_moqt_io g_io = {
    io_open_bidi_stream,
    wired_server_wt_stream_send,
    io_send_uni,
    io_open_uni_stream,
    wired_server_wt_stream_fin,
    wired_server_wt_stream_reset,
    0,
    wired_server_wt_send_datagram_to,
    wired_server_wt_stream_hold,
    io_send_budget,
    wired_server_wt_close_session,
    wired_server_wt_stream_reply_open,
    wired_server_wt_stream_priority,
    wired_server_wt_stream_stop,
};

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

static const u8 SERVER_SCID[6] = {'M', 'O', 'Q', 'I', 'O', 'P'};

typedef struct {
  u8 priv[32];
  u8 pub[32];
  u8 seed[32];
  u8 rnd[32];
} server_keys;

/* Fixed demo identity; --cert/--key replace the self-signed certificate. */
static void server_identity(wired_srvboot_id* id, server_keys* k) {
  for (usz i = 0; i < 32; i++) {
    k->priv[i] = (u8)(0x50 + i);
    k->seed[i] = (u8)(0x90 + i);
    k->rnd[i]  = (u8)(0xb0 + i);
  }
  wired_x25519_base(k->pub, k->priv);
  id->priv                    = k->priv;
  id->pub                     = k->pub;
  id->cert_seed               = k->seed;
  id->scid                    = SERVER_SCID;
  id->scid_len                = sizeof SERVER_SCID;
  id->random                  = k->rnd;
  id->max_datagram_frame_size = 65535;
  id->now_secs                = wired_clock_epoch_secs();
}

__attribute__((force_align_arg_pointer, used)) int wired_main(
    int argc, char** argv) {
  static wired_certreload_store cert_store;
  wired_srvboot_id              id = {0};
  server_keys                   keys;
  wired_srvdriver_opt           opt;
  wired_srvrun_handler          h   = {.cb = app_on_request};
  wired_srvrun_obs              obs = {
      wired_cliargs_str(argc, argv, "--qlog", 0),
      wired_cliargs_str(argc, argv, "--keylog", 0),
      wired_cliargs_str(argc, argv, "--cert", 0),
      wired_cliargs_str(argc, argv, "--key", 0), 0};

  server_identity(&id, &keys);
  wired_certreload_load_or_selfsigned(
      obs.cert_path, obs.key_path, &cert_store, &id);
  wired_moqt_init(&g_hub, g_io);
  wired_moqt_cache_attach(&g_hub, g_cache_arena, sizeof g_cache_arena);

  if (!wired_srvdriver_parse(argc, argv, &opt))
    wired_die("bad CLI flags (single-process only)\n");
  static char wt_protocols[32];
  wired_moqt_wt_protocols(wt_protocols, sizeof wt_protocols);

  opt.run.incoming_cpu            = -1;
  opt.run.wt_protocols            = wt_protocols;
  opt.run.wt_on_session           = wired_moqt_on_session;
  opt.run.wt_session_ctx          = &g_hub;
  opt.run.wt_on_stream_data       = wired_moqt_on_stream_data;
  opt.run.wt_stream_data_ctx      = &g_hub;
  opt.run.wt_on_datagram          = wired_moqt_on_datagram;
  opt.run.wt_datagram_ctx         = &g_hub;
  opt.run.wt_on_stream_reset      = wired_moqt_on_stream_reset;
  opt.run.wt_stream_reset_ctx     = &g_hub;
  opt.run.wt_on_session_close     = wired_moqt_on_session_close;
  opt.run.wt_session_close_ctx    = &g_hub;
  opt.run.wt_on_session_draining  = wired_moqt_on_session_draining;
  opt.run.wt_session_draining_ctx = &g_hub;
  opt.run.on_step                 = on_step;
  opt.run.on_step_ctx             = &g_hub;

  if (!wired_srvdriver_run(&id, h, obs, &opt)) wired_die("listen failed\n");
  return 0;
}
