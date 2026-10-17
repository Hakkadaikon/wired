/* webtransport_interop's passive transfer: answering the client's GETs. */

#include "wt_interop.h"

/* --- static send buffers (view-based send APIs need stable storage) ------ */

#define POOL_SLOTS 6
#define POOL_HEAD 128
#define POOL_BODY (2u * 1024 * 1024)
#define DG_SLOTS 200
#define DG_CAP 1152

/* ponytail: round-robin, never freed -- 6 slots cover the runner's 5
 * concurrent stream transfers; grow POOL_SLOTS if a test overlaps more. */
static u8  g_pool[POOL_SLOTS][POOL_HEAD + POOL_BODY];
static usz g_pool_next;
static u8  g_dg[DG_SLOTS][DG_CAP]; /* datagram files are sub-MTU by contract */
static usz g_dg_next;

static u8* pool_take(void) {
  u8* p       = g_pool[g_pool_next];
  g_pool_next = (g_pool_next + 1) % POOL_SLOTS;
  return p;
}

static u8* dg_take(void) {
  u8* p     = g_dg[g_dg_next];
  g_dg_next = (g_dg_next + 1) % DG_SLOTS;
  return p;
}

/* Signal prefix + "PUSH <basename>\n" into slot; their total length, or 0
 * when either does not fit. */
static usz uni_push_head(u8* slot, const wired_wt_session* s, wired_span file) {
  usz sig  = wired_wtwire_signal_put(slot, POOL_HEAD, 0, s->connect_stream_id);
  usz head = wired_wtwire_push_head_put(
      slot + sig, POOL_HEAD - sig, wired_wtwire_basename(file));
  return sig && head ? sig + head : 0;
}

/* Client uni "GET <file>": signal prefix + "PUSH <basename>\n" + content on
 * a NEW uni stream, closed after the payload (the SDK adds the FIN). */
static void serve_uni_get(wired_wt_session* s, wired_span ep, wired_span file) {
  u8* slot = pool_take();
  usz head = uni_push_head(slot, s, file);
  ssz got;
  if (head == 0) {
    return;
  }
  got = wti_www_read(ep, file, wired_mspan_of(slot + head, POOL_BODY));
  if (got < 0) {
    return; /* missing file: ignore, keep serving */
  }
  wired_server_wt_open_uni(s, wired_span_of(slot, head + (usz)got));
}

/* Client bidi "GET <file>": bare content back on the SAME stream. */
static void serve_bidi_get(
    wired_wt_session* s, u64 stream_id, wired_span ep, wired_span file) {
  u8* slot = pool_take();
  ssz got  = wti_www_read(ep, file, wired_mspan_of(slot, POOL_BODY));
  if (got < 0) {
    return;
  }
  wired_server_wt_stream_reply(s, stream_id, wired_span_of(slot, (usz)got));
}

/* Datagram "GET <file>": one "PUSH <basename>\n" + content datagram back
 * (the SDK adds the quarter-stream-id prefix). */
static void serve_dg_get(wired_wt_session* s, wired_span ep, wired_span file) {
  u8* slot = dg_take();
  usz head =
      wired_wtwire_push_head_put(slot, DG_CAP, wired_wtwire_basename(file));
  ssz got;
  if (head == 0) {
    return;
  }
  got = wti_www_read(ep, file, wired_mspan_of(slot + head, DG_CAP - head));
  if (got < 0) {
    return;
  }
  wired_server_wt_send_datagram_to(s, wired_span_of(slot, head + (usz)got));
}

/* Full "GET <file>" line gathered (FIN seen): answer by stream type.
 * RFC 9000 2.1: a client-initiated uni stream has id % 4 == 2. */
void wti_serve_get(wired_wt_session* s, u64 stream_id, wired_span line) {
  wired_span file;
  wired_span ep = wti_session_endpoint(s);
  if (!wired_wtwire_get_parse(line, &file)) {
    return;
  }
  if ((stream_id & 3) == 2) {
    serve_uni_get(s, ep, file);
  } else {
    serve_bidi_get(s, stream_id, ep, file);
  }
}

void wti_dg_serve(wired_wt_session* s, wired_span msg) {
  wired_span file;
  if (!wired_wtwire_get_parse(msg, &file)) {
    return;
  }
  serve_dg_get(s, wti_session_endpoint(s), file);
}
