/* webtransport_interop's active send modes: issue every GET once the
 * REQUESTS session is established, and save the client's replies. */

#include "wt_interop.h"

/* Room for the stream signal prefix (2-byte varint type + up to 8-byte
 * varint session id) written ahead of a GET line for uni/bidi opens. */
#define GET_SIG_CAP 16

/* Signal-prefixed copies for stream opens, built once the session (and so
 * its id) is known; kept alive until the transfer completes. */
static u8  g_get_sig[FILES_MAX][GET_SIG_CAP + GETLINE_CAP];
static usz g_get_sig_len[FILES_MAX];

/* Build the signal-prefixed GET payloads for this session (uni/bidi opens
 * carry the WT stream signal ahead of the line; datagrams do not). */
static void prep_sig_gets(wired_wt_session* s, int bidi) {
  for (usz i = 0; i < wti_nfiles; i++) {
    usz sig = wired_wtwire_signal_put(
        g_get_sig[i], GET_SIG_CAP, bidi, s->connect_stream_id);
    for (usz j = 0; j < wti_get_len[i]; j++) {
      g_get_sig[i][sig + j] = wti_get[i][j];
    }
    g_get_sig_len[i] = sig + wti_get_len[i];
  }
}

static void send_gets_uni(wired_wt_session* s) {
  prep_sig_gets(s, 0);
  for (usz i = 0; i < wti_nfiles; i++) {
    wired_server_wt_open_uni(s, wired_span_of(g_get_sig[i], g_get_sig_len[i]));
  }
}

static void send_gets_bidi(wired_wt_session* s) {
  prep_sig_gets(s, 1);
  for (usz i = 0; i < wti_nfiles; i++) {
    i64 sid = wired_server_wt_open_bidi(
        s, wired_span_of(g_get_sig[i], g_get_sig_len[i]));
    if (sid >= 0) {
      wti_body_slot_open((u64)sid, wti_files[i]);
    }
  }
}

/* Datagram GETs go out as a reply-clocked window, not one burst: datagrams
 * are never retransmitted (RFC 9221 5), and every GET triggers a ~1KB reply,
 * so the request rate IS the reply rate -- 200 requests at once made the
 * client's replies overflow the 10Mbps path's 25-packet queue and the
 * dropped files were gone for good. With at most DG_WINDOW requests in
 * flight, each saved reply releases the next request, so neither direction
 * ever queues more than DG_WINDOW packets. */
#define DG_WINDOW 8

static wired_wt_session* g_dg_sess;     /* the one DG_SEND session per run */
static usz               g_dg_req_next; /* next file index not yet requested */
static u8                g_dg_done[FILES_MAX];

static void dg_request_one(usz i) {
  wired_server_wt_send_datagram_to(
      g_dg_sess, wired_span_of(wti_get[i], wti_get_len[i]));
}

static void send_gets_dg(wired_wt_session* s) {
  usz w     = wti_nfiles < DG_WINDOW ? wti_nfiles : DG_WINDOW;
  g_dg_sess = s;
  for (g_dg_req_next = 0; g_dg_req_next < w; g_dg_req_next++) {
    dg_request_one(g_dg_req_next);
  }
}

static ssz dg_file_index(wired_span name) {
  for (usz i = 0; i < wti_nfiles; i++) {
    if (wired_span_eq(wti_files[i], name)) {
      return (ssz)i;
    }
  }
  return -1;
}

static void dg_request_next(void) {
  if (g_dg_req_next < wti_nfiles) {
    dg_request_one(g_dg_req_next++);
  }
}

/* One reply saved: mark its file done and release the next request; a
 * duplicate or unknown name releases nothing (the window stays honest).
 * Returns 1 when the name was newly marked done. */
static int dg_mark_done(wired_span name) {
  ssz i = dg_file_index(name);
  if (i < 0) {
    return 0;
  }
  if (g_dg_done[i]) {
    return 0;
  }
  g_dg_done[i] = 1;
  dg_request_next();
  return 1;
}

typedef void (*send_fn)(wired_wt_session*);

static const send_fn SENDS[MODE_COUNT] = {
    0,              /* MODE_HANDSHAKE */
    0,              /* MODE_TRANSFER */
    send_gets_uni,  /* MODE_UNI_SEND */
    send_gets_bidi, /* MODE_BIDI_SEND */
    send_gets_dg,   /* MODE_DG_SEND */
};

/* A session for the REQUESTS endpoint in a send mode: issue every GET. */
void wti_send_gets(wired_wt_session* s, wired_span path) {
  if (SENDS[wti_mode] && wired_span_eq(wti_endpoint_of(path), wti_endpoint)) {
    SENDS[wti_mode](s);
  }
}

/* One PUSH datagram carries a whole (sub-MTU) file. */
void wti_dg_save(wired_wt_session* s, wired_span msg) {
  wired_span name, content;
  char       dest[PATH_CAP];
  if (!wired_wtwire_push_parse(msg, &name, &content)) {
    return;
  }
  wti_dest_build(dest, wired_wtwire_basename(name));
  wired_fio_write_new(dest, content);
  /* release the next request; a fresh save also counts toward the close */
  if (dg_mark_done(wired_wtwire_basename(name))) {
    wti_note_saved(s);
  }
}
