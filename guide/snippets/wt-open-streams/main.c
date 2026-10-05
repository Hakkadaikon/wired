#define WIRED_MAIN
#include "wired.h"

/* The one server-opened uni stream this single-session demo keeps open
 * across several rounds, appended to from on_stream_data below. */
static i64 g_uni = -1;

/* Open it on connect, WITHOUT closing: wired_server_wt_open_uni_stream
 * (unlike wired_server_wt_open_uni) leaves the stream open for further
 * wired_server_wt_stream_send rounds. */
static void on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  (void)ctx;
  (void)path;
  (void)protocol;
  u8  buf[16];
  usz n = wired_wtwire_signal_put(buf, sizeof buf, 0, s->connect_stream_id);
  memcpy(buf + n, "chunk1 ", 7);
  g_uni = wired_server_wt_open_uni_stream(s, wired_span_of(buf, n + 7));
}

/* The client drives the open stream over its own bidi requests: "more"
 * appends a round (fin=0, stays open), "bye" appends the closing round
 * (fin=1). Each request gets a short reply once applied. */
static void on_stream_data(
    void* ctx, wired_wt_session* s, u64 stream_id, wired_span data, int fin) {
  (void)ctx;
  if (!fin) return;
  if (wired_span_eq_cstr(data, "more"))
    wired_server_wt_stream_send(
        s, (u64)g_uni, wired_span_of((const u8*)"chunk2 ", 7), 0);
  else if (wired_span_eq_cstr(data, "bye"))
    wired_server_wt_stream_send(
        s, (u64)g_uni, wired_span_of((const u8*)"chunk3", 6), 1);
  wired_server_wt_stream_reply(s, stream_id, wired_span_of((const u8*)"ok", 2));
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-wt");
  id.max_datagram_frame_size = 65535; /* WebTransport requires DATAGRAM */

  wired_srvrun_opt opt  = {0};
  opt.incoming_cpu      = -1;
  opt.wt_on_session     = on_session;
  opt.wt_on_stream_data = on_stream_data;

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
