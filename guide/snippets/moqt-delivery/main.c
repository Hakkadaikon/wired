#define WIRED_MAIN
#include "app/moqt/data/moqdata.h"
#include "app/moqt/dgram/moqdg.h"
#include "wired.h"

/* A server-opened WebTransport stream starts with the stream signal (stream
 * type + session id), the same wrapper moqt-publish/moqt-hub use. */
static u8 g_out[20100];

static wired_span with_signal(wired_wt_session* s, wired_span msg) {
  usz n = wired_wtwire_signal_put(g_out, sizeof g_out, 0, s->connect_stream_id);
  if (n == 0 || msg.n > sizeof g_out - n) return wired_span_of(g_out, 0);
  memcpy(g_out + n, msg.p, msg.n);
  return wired_span_of(g_out, n + msg.n);
}

/* Bigger than MOQDATA_BLOB_CHUNK (16384), so the stream delivery below
 * demonstrates the per-Object cap by arriving as two Objects, not one. */
#define BLOB_LEN 20000
static u8 g_blob[BLOB_LEN];
static u8 g_wire[MOQDATA_BLOB_WIRE_CAP(BLOB_LEN)];

/* Any datagram from the client is just a "go ahead" trigger (content
 * unchecked): send one lossy OBJECT_DATAGRAM (draft-ietf-moq-transport-19
 * 11.3.1), then one reliable Object stream (11.4.2) whose blob exceeds the
 * 16 KiB per-Object cap and so arrives chunked into two Objects. */
static void on_datagram(void* ctx, wired_wt_session* s, wired_span data) {
  (void)ctx;
  (void)data;

  u8        dg[32];
  usz       off = 0;
  moqdg_obj o   = {0};
  o.track_alias = 2;
  o.payload     = wired_span_of((const u8*)"ping-obj", 8);
  if (moqdg_put(wired_mspan_of(dg, sizeof dg), &off, &o) == MOQDATA_OK)
    wired_server_wt_send_datagram_to(s, wired_span_of(dg, off));

  usz n = moqdata_blob_build(
      wired_mspan_of(g_wire, sizeof g_wire), 1, wired_span_of(g_blob, BLOB_LEN));
  wired_span framed = n ? with_signal(s, wired_span_of(g_wire, n))
                        : wired_span_of(g_out, 0);
  if (framed.n) wired_server_wt_open_uni(s, framed);
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static u8       priv[32], pub[32], seed[32], rnd[32];
  static const u8 scid[] = "guide-md";
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
  id.max_datagram_frame_size = 65535; /* WebTransport requires DATAGRAM */

  for (usz i = 0; i < BLOB_LEN; i++) g_blob[i] = (u8)('a' + i % 26);

  wired_srvrun_opt opt = {0};
  opt.incoming_cpu     = -1;
  opt.wt_on_datagram   = on_datagram;

  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h    = {0};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
