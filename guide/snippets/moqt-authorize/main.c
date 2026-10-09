#define WIRED_MAIN
#include "app/moqt/qraw/moqrawio.h"
#include "app/moqt/run/moqtrun.h"
#include "wired.h"

/* draft-ietf-moq-transport-19 SS13.3 subscriber authorization: this
 * sample's policy grants "public" and refuses everything else (the token
 * carries CAT/Privacy Pass in a real deployment; this demo ignores it). */
static int authorize(
    void* ctx, const moqctl_ftn* name, const moqctl_token* token) {
  (void)ctx;
  (void)token;
  return wired_span_eq_cstr(name->name, "public");
}

static wired_moqt_hub g_hub;

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the other MoQT pages, plus QUIC
   * DATAGRAM support. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-az");
  id.max_datagram_frame_size = 65535;

  wired_moqt_io io = wired_moqraw_io();
  wired_moqt_init(&g_hub, io);
  g_hub.authorize_subscribe = authorize;

  /* The hub holds exactly one blob track at a time (a second publish
   * would replace it), so "secret" is never published at all: the policy
   * below refuses it before matching ever runs, the same outcome a real
   * relay wants for a track its policy will never grant regardless of
   * whether it exists. */
  static u8 public_wire[MOQDATA_BLOB_WIRE_CAP(2)];
  wired_moqt_publish_blob(
      &g_hub, wired_span_cstr("public"), 1,
      wired_span_cstr("ok"),
      wired_mspan_of(public_wire, sizeof public_wire));

  /* The hub owns every WebTransport session: it sends SETUP when one opens,
   * answers the control messages that arrive, and forgets it on close. */
  wired_srvrun_opt opt     = {0};
  opt.incoming_cpu         = -1;
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
