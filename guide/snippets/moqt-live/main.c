#define WIRED_MAIN
#include "app/media/mp4frag/mp4frag.h"
#include "app/moqt/qraw/moqrawio.h"
#include "app/moqt/run/moqtrun.h"
#include "common/platform/clock/mono.h"
#include "wired.h"

/* send_uni2 (moqtrun.h): a live Group's framing (head) plus the fragment
 * bytes (body, a view this file does not own) go out on their own fresh
 * uni stream. wired_server_wt_open_uni holds a payload past its staging
 * as a VIEW until ACKed (srvrun.h), so the signal+head+body bytes must
 * stay put until then -- a single reused buffer would risk splicing a
 * later Group into an earlier one still in flight (the exact bug
 * examples/moqt_chat's send_uni2 comment documents). This demo expects
 * one session and a handful of small Groups, so a 2-slot ring (reused
 * once wired_server_wt_stream_inflight reports the slot's stream done) is
 * enough; a multi-session server needs one ring per session (see
 * examples/moqt_chat/wired_server.c). */
#define LIVE_RING 2
#define LIVE_SLOT_CAP 128
typedef struct {
  u64 stream_id;
  int used;
  u8  buf[LIVE_SLOT_CAP];
} live_slot;
static wired_wt_session* g_live_session;
static live_slot         g_live_ring[LIVE_RING];

static int live_slot_free(const live_slot* slot) {
  if (!slot->used) return 1;
  return !wired_server_wt_stream_inflight(g_live_session, slot->stream_id);
}

static live_slot* live_slot_claim(void) {
  for (usz i = 0; i < LIVE_RING; i++)
    if (live_slot_free(&g_live_ring[i])) return &g_live_ring[i];
  return 0;
}

static i64 send_uni2(wired_wt_session* s, wired_span head, wired_span body) {
  live_slot* slot = live_slot_claim();
  usz        sig;
  if (!slot || head.n + body.n > sizeof slot->buf - 9) return -1;
  g_live_session = s;
  sig            = wired_wtwire_signal_put(
      slot->buf, sizeof slot->buf, 0, s->connect_stream_id);
  if (sig == 0) return -1;
  memcpy(slot->buf + sig, head.p, head.n);
  memcpy(slot->buf + sig + head.n, body.p, body.n);
  i64 sid = wired_server_wt_open_uni(
      s, wired_span_of(slot->buf, sig + head.n + body.n));
  if (sid >= 0) {
    slot->stream_id = (u64)sid;
    slot->used      = 1;
  }
  return sid;
}

static wired_moqt_hub g_hub;
static mp4frag_layout g_layout;

static void on_step(void* ctx, u64 now_ms) {
  wired_moqt_tick((wired_moqt_hub*)ctx, now_ms);
}

/* Group 0 starts not at server boot but at the first WebTransport session
 * -- otherwise Group 0's window includes the client's own connect/
 * handshake latency, which on a loaded machine can exceed group_ms and
 * make the first Group (and so the whole fragment-size sequence the page
 * prints) nondeterministic. Anchoring here instead means the only
 * latency left before the first SUBSCRIBE is one already-established
 * QUIC round trip (SETUP out, SUBSCRIBE back), far inside the margin. */
static int g_live_published = 0;

static void publish_live_once(void) {
  if (g_live_published) return;
  g_live_published = 1;
  wired_moqt_publish_live(
      &g_hub, wired_span_cstr("movie"), 2, g_layout.frags,
      g_layout.n_frags, 300, clock_mono_ms());
}

static void on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  publish_live_once();
  wired_moqt_on_session(ctx, s, path, protocol);
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the other MoQT pages, plus QUIC
   * DATAGRAM support. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-lv");
  id.max_datagram_frame_size = 65535;

  wired_moqt_io io = wired_moqraw_io();
  io.send_uni2     = send_uni2;
  wired_moqt_init(&g_hub, io);

  /* movie-live.mp4 (committed next to this file, see gen_movie.py) is a
   * tiny synthetic fragmented MP4: an ftyp+moov init segment, then 3
   * moof+mdat fragments -- real box structure, filler media bytes (this
   * demo is about MoQT Group delivery, not video decoding). */
  static u8 file[4096];
  ssz n = wired_fio_read("movie-live.mp4", wired_mspan_of(file, sizeof file));
  if (n <= 0 || !mp4frag_scan(wired_span_of(file, (usz)n), &g_layout)) {
    wired_log_str("cannot scan movie-live.mp4\n");
    return 1;
  }

  /* "movie/init" (Track Alias 1): the init segment, sent once per
   * subscriber on its own stream (wired_moqt_publish_blob). */
  static u8 init_wire[MOQDATA_BLOB_WIRE_CAP(64)];
  wired_moqt_publish_blob(
      &g_hub, wired_span_cstr("movie/init"), 1, g_layout.init,
      wired_mspan_of(init_wire, sizeof init_wire));

  /* "movie" (Track Alias 2): Group g carries fragment g mod n_frags,
   * advancing every 300ms (RFC-agnostic: draft-ietf-moq-transport-19
   * 9.x's Group model) -- publish_live_once (above) defers the actual
   * wired_moqt_publish_live call to the first WebTransport session so
   * Group 0 starts there, not at this still-booting instant. */
  wired_srvrun_opt opt     = {0};
  opt.incoming_cpu         = -1;
  opt.on_step              = on_step;
  opt.on_step_ctx          = &g_hub;
  opt.wt_on_session        = on_session;
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
