#define WIRED_MAIN
#include "app/moqt/run/moqtrun.h"
#include "wired.h"

/* A server-opened WebTransport stream starts with the stream signal (stream
 * type + session id), the same wrapper moqt-hub uses. The SDK copies a
 * payload this small before returning, so one buffer serves every call. */
static u8 g_out[4096];

static wired_span with_signal(wired_wt_session* s, int bidi, wired_span msg) {
  usz n = wired_wtwire_signal_put(g_out, sizeof g_out, bidi, s->connect_stream_id);
  if (n == 0 || msg.n > sizeof g_out - n) return wired_span_of(g_out, 0);
  memcpy(g_out + n, msg.p, msg.n);
  return wired_span_of(g_out, n + msg.n);
}

static i64 open_bidi(wired_wt_session* s, wired_span msg) {
  wired_span out = with_signal(s, 1, msg);
  return out.n ? wired_server_wt_open_bidi_stream(s, out) : -1;
}

/* 1 if field equals the literal lit. */
static int field_is(wired_span field, const char* lit) {
  usz i = 0;
  while (i < field.n && lit[i] == (char)field.p[i]) i++;
  return i == field.n && lit[i] == 0;
}

/* draft-ietf-moq-transport-19 10.15 / 10.18: the hub asks this hook before
 * it accepts a PUBLISH_NAMESPACE or SUBSCRIBE_NAMESPACE. This sample's
 * policy refuses any namespace ending in "secret" (a real deployment
 * would verify the token too; this demo ignores it). */
static int authorize_ns(void* ctx, u64 msg_type, const moqctl_ns* ns, const moqctl_token* token) {
  (void)ctx;
  (void)msg_type;
  (void)token;
  return ns->n == 0 || !field_is(ns->fields[ns->n - 1], "secret");
}

static wired_moqt_hub g_hub;

static void on_step(void* ctx, u64 now_ms) {
  wired_moqt_tick((wired_moqt_hub*)ctx, now_ms);
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the other MoQT pages, plus QUIC
   * DATAGRAM support, which WebTransport clients ask for. */
  static u8       priv[32], pub[32], seed[32], rnd[32];
  static const u8 scid[] = "guide-nd";
  wired_srvboot_id id = {0};
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x50 + i);
    seed[i] = (u8)(0x90 + i);
    rnd[i]  = (u8)(0xb0 + i);
  }
  wired_x25519_base(pub, priv);
  id.priv                    = priv;
  id.pub                     = pub;
  id.cert_seed               = seed;
  id.random                  = rnd;
  id.scid                    = scid;
  id.scid_len                = sizeof scid - 1; /* without the string's NUL */
  id.max_datagram_frame_size = 65535;

  /* PUBLISH_NAMESPACE and SUBSCRIBE_NAMESPACE arrive on the client's own
   * bidi streams (draft-ietf-moq-transport-19 3.3) and stay open: the hub
   * answers on them through stream_reply_open, and later pushes NAMESPACE /
   * NAMESPACE_DONE onto the subscriber's stream with stream_send. */
  wired_moqt_io io = {
      .open_bidi_stream  = open_bidi,
      .stream_send       = wired_server_wt_stream_send,
      .stream_fin        = wired_server_wt_stream_fin,
      .stream_reset      = wired_server_wt_stream_reset,
      .stream_reply_open = wired_server_wt_stream_reply_open,
  };
  wired_moqt_init(&g_hub, io);
  g_hub.authorize_namespace = authorize_ns;

  /* on_session_close withdraws every namespace a leaving session
   * published (NAMESPACE_DONE to its watchers); the tick retries a push
   * the transport refused. */
  wired_srvrun_opt opt = {
      .incoming_cpu         = -1,
      .on_step              = on_step,
      .on_step_ctx          = &g_hub,
      .wt_on_session        = wired_moqt_on_session,
      .wt_session_ctx       = &g_hub,
      .wt_on_stream_data    = wired_moqt_on_stream_data,
      .wt_stream_data_ctx   = &g_hub,
      .wt_on_stream_reset   = wired_moqt_on_stream_reset,
      .wt_stream_reset_ctx  = &g_hub,
      .wt_on_session_close  = wired_moqt_on_session_close,
      .wt_session_close_ctx = &g_hub,
  };

  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h    = {0};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
