#define WIRED_MAIN
#include "wired.h"

/* The hub calls this right after it opens a subscriber stream, with the
 * RFC 9218 urgency WIRED_MOQTRUN_URGENCY computed from the subscription's
 * Subscriber Priority and the stream's Publisher Priority. Logging it makes
 * the mapping visible; the scheduling itself is wired_server_wt_stream_
 * priority's job (lower urgency is sent first). */
static int stream_priority(wired_wt_session* s, u64 stream_id, u8 urgency) {
  wired_dprintf(2, "subscriber stream urgency=%u\n", urgency);
  return wired_server_wt_stream_priority(s, stream_id, urgency);
}

static wired_moqt_hub g_hub;

/* Any datagram is the operator's "drain now" trigger in this demo (a real
 * server would call this on SIGTERM or before a deploy). Every session
 * gets GOAWAY pointing at the new URI, with 300 ms to leave (short so the
 * page's client stays well inside its own deadline; the hub still waits
 * WIRED_MOQTRUN_GOAWAY_GRACE_MS past that before it actually closes). */
static void on_datagram(void* ctx, wired_wt_session* s, wired_span data) {
  (void)s;
  (void)data;
  static const char uri[] = "https://relay2.example/moqt";
  wired_moqt_goaway((wired_moqt_hub*)ctx, wired_span_cstr(uri), 300);
  wired_log_str("GOAWAY sent\n");
}

/* The tick enforces the GOAWAY Timeout: PUBLISH_DONE once it passes, the
 * session close on the tick after. */
static void on_step(void* ctx, u64 now_ms) {
  wired_moqt_tick((wired_moqt_hub*)ctx, now_ms);
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the other MoQT pages, plus QUIC
   * DATAGRAM support, which WebTransport clients ask for. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-pg");
  id.max_datagram_frame_size = 65535;

  /* stream_priority turns the subscription's priority into stream
   * urgency; stream_reset and close_session are what the drain uses to
   * end subscriptions and sessions once the GOAWAY Timeout passes. GOAWAY
   * itself goes out on the hub's uni control stream ("moqt-22", 9.2). */
  wired_moqt_io io   = wired_moqraw_io();
  io.stream_priority = stream_priority;
  wired_moqt_init(&g_hub, io);

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
      .wt_on_datagram       = on_datagram,
      .wt_datagram_ctx      = &g_hub,
      .wt_on_session_close  = wired_moqt_on_session_close,
      .wt_session_close_ctx = &g_hub,
  };

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
