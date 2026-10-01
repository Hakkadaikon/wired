#define WIRED_MAIN
#include "app/moqt/run/moqtrun.h"
#include "wired.h"

/* A server-opened WebTransport stream starts with the stream signal (stream
 * type + session id). The hub hands over only the MoQT bytes, so these two
 * io entries put the signal in front. The SDK copies a payload this small
 * before returning, so one buffer serves every call. */
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

static i64 send_uni(wired_wt_session* s, wired_span msg) {
  wired_span out = with_signal(s, 0, msg);
  return out.n ? wired_server_wt_open_uni(s, out) : -1;
}

/* 1 if name's Track Name (namespace ignored, same as the rest of this
 * hub's matching -- moqtrun.c matches Track Name only) equals lit. */
static int track_name_is(const moqctl_ftn* name, const char* lit) {
  usz        i = 0;
  wired_span n = name->name;
  while (i < n.n && lit[i] == (char)n.p[i]) i++;
  return i == n.n && lit[i] == 0;
}

/* draft-ietf-moq-transport-19 SS13.3 subscriber authorization: this
 * sample's policy grants "public" and refuses everything else (the token
 * carries CAT/Privacy Pass in a real deployment; this demo ignores it). */
static int authorize(void* ctx, const moqctl_ftn* name, const moqctl_token* token) {
  (void)ctx;
  (void)token;
  return track_name_is(name, "public");
}

static wired_moqt_hub g_hub;

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the other MoQT pages, plus QUIC
   * DATAGRAM support. */
  static u8       priv[32], pub[32], seed[32], rnd[32];
  static const u8 scid[] = "guide-az";
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

  wired_moqt_io io = {0};
  io.open_bidi_stream = open_bidi;
  io.stream_send      = wired_server_wt_stream_send;
  io.send_uni         = send_uni;
  wired_moqt_init(&g_hub, io);
  g_hub.authorize_subscribe = authorize;

  /* The hub holds exactly one blob track at a time (a second publish
   * would replace it), so "secret" is never published at all: the policy
   * below refuses it before matching ever runs, the same outcome a real
   * relay wants for a track its policy will never grant regardless of
   * whether it exists. */
  static u8 public_wire[MOQDATA_BLOB_WIRE_CAP(2)];
  wired_moqt_publish_blob(
      &g_hub, wired_span_of((const u8*)"public", 6), 1,
      wired_span_of((const u8*)"ok", 2),
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

  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h    = {0};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
