#define WIRED_MAIN
#include "wired.h"

/* draft-ietf-moq-transport-22 9.14 / 9.15: the hub asks this hook before
 * it accepts a PUBLISH_NAMESPACE or SUBSCRIBE_NAMESPACE. This sample's
 * policy refuses any namespace ending in "secret" (a real deployment
 * would verify the token too; this demo ignores it). */
static int authorize_ns(
    void* ctx, u64 msg_type, const moqctl_ns* ns, const moqctl_token* token) {
  (void)ctx;
  (void)msg_type;
  (void)token;
  return ns->n == 0 || !wired_span_eq_cstr(ns->fields[ns->n - 1], "secret");
}

static wired_moqt_hub g_hub;

static void on_step(void* ctx, u64 now_ms) {
  wired_moqt_tick((wired_moqt_hub*)ctx, now_ms);
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the other MoQT pages, plus QUIC
   * DATAGRAM support, which WebTransport clients ask for. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-nd");
  id.max_datagram_frame_size = 65535;

  /* PUBLISH_NAMESPACE and SUBSCRIBE_NAMESPACE arrive on the client's own
   * bidi streams (draft-ietf-moq-transport-22 6.4.2) and stay open: the hub
   * answers on them through stream_reply_open, and later pushes NAMESPACE /
   * NAMESPACE_DONE onto the subscriber's stream with stream_send. */
  wired_moqt_io io = wired_moqraw_io();
  wired_moqt_init(&g_hub, io);
  g_hub.authorize_namespace = authorize_ns;

  /* on_session_close withdraws every namespace a leaving session
   * published (NAMESPACE_DONE to its watchers); the tick retries a push
   * the transport refused. "moqt-22" selects draft-22 (see the hub page). */
  wired_srvrun_opt opt = {
      .incoming_cpu         = -1,
      .wt_protocols         = "moqt-22",
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

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
