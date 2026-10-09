#define WIRED_MAIN
#include "app/moqt/qraw/moqrawio.h"
#include "app/moqt/run/moqtrun.h"
#include "wired.h"

static wired_moqt_hub g_hub;

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 pages, plus QUIC DATAGRAM
   * support, which WebTransport clients ask for. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-mq");
  id.max_datagram_frame_size = 65535;

  wired_moqt_io io = wired_moqraw_io();
  wired_moqt_init(&g_hub, io);

  /* The hub owns every WebTransport session. A client that offers the
   * subprotocol "moqt-22" gets draft-ietf-moq-transport-22: the hub sends
   * SETUP on a uni control stream of its own (6.3), answers each request
   * on the bidi stream it arrived on (6.4.2), and forgets it on close. */
  wired_srvrun_opt opt     = {0};
  opt.incoming_cpu         = -1;
  opt.wt_protocols         = "moqt-22";
  opt.wt_on_session        = wired_moqt_on_session;
  opt.wt_session_ctx       = &g_hub;
  opt.wt_on_stream_data    = wired_moqt_on_stream_data;
  opt.wt_stream_data_ctx   = &g_hub;
  opt.wt_on_datagram       = wired_moqt_on_datagram;
  opt.wt_datagram_ctx      = &g_hub;
  opt.wt_on_session_close  = wired_moqt_on_session_close;
  opt.wt_session_close_ctx = &g_hub;

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
