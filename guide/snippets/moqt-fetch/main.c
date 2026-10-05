#define WIRED_MAIN
#include "app/moqt/qraw/moqrawio.h"
#include "app/moqt/run/moqtrun.h"
#include "wired.h"

/* Room for exactly 4 cached Objects of the 7-byte payloads the client
 * publishes ("frame-N"): each costs MOQCACHE_HDR on top of its payload.
 * The client publishes 6 groups of one Object each, so the oldest 2 are
 * evicted and a FETCH reaching back to them gets an End of Unknown Range. */
#define FRAME_LEN 7
static u8             g_arena[4 * (MOQCACHE_HDR + FRAME_LEN)];
static wired_moqt_hub g_hub;

static void on_step(void* ctx, u64 now_ms) {
  wired_moqt_tick((wired_moqt_hub*)ctx, now_ms);
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the other MoQT pages, plus QUIC
   * DATAGRAM support, which WebTransport clients ask for. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-mf");
  id.max_datagram_frame_size = 65535;

  /* Requests arrive on the client's own bidi streams (draft-ietf-moq-
   * transport-19 3.3): stream_reply_open answers on them. A FETCH answer
   * uses open_uni_stream + stream_send rounds, and stream_reset when a
   * fetch is cancelled. */
  wired_moqt_io io = wired_moqraw_io();
  wired_moqt_init(&g_hub, io);

  /* Every whole Object a publisher sends is now kept for FETCH, oldest
   * whole groups evicted first when the arena is full. */
  wired_moqt_cache_attach(&g_hub, g_arena, sizeof g_arena);

  /* The tick retries a FETCH round the transport refused (and gives up
   * on one that stays refused). */
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

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
