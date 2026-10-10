#define WIRED_MAIN
#include "wired.h"

/* Bigger than MOQDATA_BLOB_CHUNK (16384), so the stream delivery below
 * demonstrates the per-Object cap by arriving as two Objects, not one. */
#define BLOB_LEN 20000
static u8 g_blob[BLOB_LEN];
static u8 g_wire[MOQDATA_BLOB_WIRE_CAP(BLOB_LEN)];

/* Any datagram from the client is just a "go ahead" trigger (content
 * unchecked): send one lossy OBJECT_DATAGRAM (draft-ietf-moq-transport-22
 * 11.2.1), then one reliable Object stream (11.3.1) whose blob exceeds the
 * 16 KiB per-Object cap and so arrives chunked into two Objects. */
static void on_datagram(void* ctx, wired_wt_session* s, wired_span data) {
  (void)ctx;
  (void)data;

  u8        dg[32];
  usz       off = 0;
  moqdg_obj o   = {0};
  o.track_alias = 2;
  o.payload     = wired_span_cstr("ping-obj");
  if (moqdg_put(wired_mspan_of(dg, sizeof dg), &off, &o) == MOQDATA_OK)
    wired_server_wt_send_datagram_to(s, wired_span_of(dg, off));

  usz n = moqdata_blob_build(
      wired_mspan_of(g_wire, sizeof g_wire), 1,
      wired_span_of(g_blob, BLOB_LEN));
  if (n) wired_moqraw_io().send_uni(s, wired_span_of(g_wire, n));
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-md");
  id.max_datagram_frame_size = 65535; /* WebTransport requires DATAGRAM */

  for (usz i = 0; i < BLOB_LEN; i++) g_blob[i] = (u8)('a' + i % 26);

  /* No hub here, so no SETUP or requests: the "moqt-22" subprotocol only
   * says the session speaks draft-22's data plane. */
  wired_srvrun_opt opt = {0};
  opt.incoming_cpu     = -1;
  opt.wt_protocols     = "moqt-22";
  opt.wt_on_datagram   = on_datagram;

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
