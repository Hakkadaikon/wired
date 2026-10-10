#include "app/moqt/qraw/moqrawio.h"

#include "app/webtransport/wtwire/wtwire.h"
#include "common/bytes/util/bytes.h"

/* The ops carry no context, so the backend is process-wide (moqrawio.h). */
static const moqrawio_backend* g_moqrawio_be;
/* One opening payload staged per call; srvrun copies it during the call. */
static u8 g_moqrawio_buf[MOQRAWIO_STAGE_BUF];

typedef i64 (*moqrawio_open_fn)(wired_wt_session* s, wired_span payload);

/* WT stream signal (draft-ietf-webtrans-http3-15 4.2) staged at the buffer
 * head; a raw-QUIC stream carries none (-19 3.3, -22 6.3). */
static usz moqrawio_sig(wired_wt_session* s, int bidi) {
  if (g_moqrawio_be->is_raw(s)) return 0;
  return wired_wtwire_signal_put(
      g_moqrawio_buf, sizeof g_moqrawio_buf, bidi, s->connect_stream_id);
}

static i64 moqrawio_open(
    moqrawio_open_fn open, int bidi, wired_wt_session* s, wired_span p) {
  usz sig = moqrawio_sig(s, bidi);
  if (p.n > sizeof g_moqrawio_buf - sig) return -1;
  bytes_memcpy(g_moqrawio_buf + sig, p.p, p.n);
  return open(s, wired_span_of(g_moqrawio_buf, sig + p.n));
}

/* The hub's own request streams (upstream SUBSCRIBE, PUBLISH) open on raw
 * sessions too, with no signal (moqrawio_sig). */
static i64 moqrawio_open_bidi(wired_wt_session* s, wired_span p) {
  return moqrawio_open(g_moqrawio_be->open_bidi_stream, 1, s, p);
}

static i64 moqrawio_send_uni(wired_wt_session* s, wired_span p) {
  return moqrawio_open(g_moqrawio_be->open_uni, 0, s, p);
}

static i64 moqrawio_open_uni_stream(wired_wt_session* s, wired_span p) {
  return moqrawio_open(g_moqrawio_be->open_uni_stream, 0, s, p);
}

/* Raw has no session-level credit (RFC 9000 4.1 is srvrun's); a WT peer
 * that never sent WT_MAX_DATA has no limit either. */
static int moqrawio_unlimited(wired_wt_session* s) {
  return g_moqrawio_be->is_raw(s) || s->max_data == 0;
}

static usz moqrawio_send_budget(wired_wt_session* s) {
  if (moqrawio_unlimited(s)) return (usz)-1;
  return s->max_data > s->sent_data ? (usz)(s->max_data - s->sent_data) : 0;
}

wired_moqt_io moqrawio_io(const moqrawio_backend* be) {
  g_moqrawio_be = be;
  return (wired_moqt_io){
      .open_bidi_stream  = moqrawio_open_bidi,
      .stream_send       = wired_server_wt_stream_send,
      .send_uni          = moqrawio_send_uni,
      .open_uni_stream   = moqrawio_open_uni_stream,
      .stream_fin        = wired_server_wt_stream_fin,
      .stream_reset      = wired_server_wt_stream_reset,
      .send_uni2         = 0,
      .send_datagram     = wired_server_wt_send_datagram_to,
      .stream_hold       = wired_server_wt_stream_hold,
      .send_budget       = moqrawio_send_budget,
      .close_session     = wired_server_wt_close_session,
      .stream_reply_open = wired_server_wt_stream_reply_open,
      .stream_priority   = wired_server_wt_stream_priority,
      .stream_stop       = wired_server_wt_stream_stop,
      .est_kbps          = wired_server_wt_est_kbps,
  };
}

static const moqrawio_backend g_moqrawio_srv = {
    wired_server_session_is_raw,
    wired_server_wt_open_bidi_stream,
    wired_server_wt_open_uni,
    wired_server_wt_open_uni_stream,
};

wired_moqt_io wired_moqraw_io(void) { return moqrawio_io(&g_moqrawio_srv); }
