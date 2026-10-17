/* webtransport_interop's per-stream receive state: one handler per state,
 * fed every received stream chunk. */

#include "wt_interop.h"

enum {
  ST_FREE,      /* unused slot */
  ST_GET,       /* passive: gathering a "GET <file>" line until FIN */
  ST_PUSH_HEAD, /* uni-send: waiting for the "PUSH <name>\n" header */
  ST_PUSH_BODY, /* uni-send: appending content to /downloads */
  ST_BODY       /* bidi-send: appending the bare reply to /downloads */
};

typedef struct {
  int  state;
  u64  stream_id;
  usz  head_len;
  u8   head[512];
  char dest[PATH_CAP];
} stream_slot;

#define STREAMS_MAX 16
static stream_slot g_streams[STREAMS_MAX];

static int stream_is(const stream_slot* e, u64 id) {
  return e->state != ST_FREE && e->stream_id == id;
}

static stream_slot* stream_find(u64 id) {
  for (usz i = 0; i < STREAMS_MAX; i++) {
    if (stream_is(&g_streams[i], id)) {
      return &g_streams[i];
    }
  }
  return 0;
}

static stream_slot* stream_alloc(void) {
  for (usz i = 0; i < STREAMS_MAX; i++) {
    if (g_streams[i].state == ST_FREE) {
      return &g_streams[i];
    }
  }
  return 0;
}

/* Initial state of a stream the PEER opened, by test-case mode. Send modes
 * other than uni-send expect no peer-opened streams (bidi-send replies
 * arrive on streams this server opened, pre-registered as ST_BODY). */
static int mode_new_stream_state(void) {
  if (wti_mode == MODE_TRANSFER) {
    return ST_GET;
  }
  return wti_mode == MODE_UNI_SEND ? ST_PUSH_HEAD : ST_FREE;
}

static stream_slot* stream_open(u64 id) {
  int          st = mode_new_stream_state();
  stream_slot* e  = st == ST_FREE ? 0 : stream_alloc();
  if (!e) {
    return 0;
  }
  e->state     = st;
  e->stream_id = id;
  e->head_len  = 0;
  return e;
}

/* Register the reply stream (same id) before the peer's bytes arrive, so
 * wti_on_stream_data streams them to the right /downloads file. */
void wti_body_slot_open(u64 sid, wired_span file) {
  stream_slot* e = stream_alloc();
  if (!e) {
    return;
  }
  e->state     = ST_BODY;
  e->stream_id = sid;
  e->head_len  = 0;
  wti_dest_build(e->dest, wired_wtwire_basename(file));
  wired_fio_write_new(e->dest, wired_span_of(0, 0));
}

/* --- feeding received stream chunks, one handler per state --------------- */

static void head_append(stream_slot* e, wired_span d) {
  usz i;
  for (i = 0; i < d.n && e->head_len < sizeof e->head; i++) {
    e->head[e->head_len++] = d.p[i];
  }
}

static void feed_none(
    wired_wt_session* s, stream_slot* e, wired_span d, int fin) {
  (void)s;
  (void)e;
  (void)d;
  (void)fin;
}

static void feed_get(
    wired_wt_session* s, stream_slot* e, wired_span d, int fin) {
  head_append(e, d);
  if (fin) {
    wti_serve_get(s, e->stream_id, wired_span_of(e->head, e->head_len));
    e->state = ST_FREE;
  }
}

/* Header complete: parse the name from head[0..head_n), create the download
 * file with this chunk's content bytes past the newline, keep appending. */
static void push_start(
    wired_wt_session* s, stream_slot* e, usz head_n, wired_span rest, int fin) {
  wired_span name, content;
  if (!wired_wtwire_push_parse(
          wired_span_of(e->head, head_n), &name, &content)) {
    e->state = ST_FREE;
    return;
  }
  wti_dest_build(e->dest, wired_wtwire_basename(name));
  wired_fio_write_new(e->dest, rest);
  e->state = ST_PUSH_BODY;
  if (fin) {
    e->state = ST_FREE;
    wti_note_saved(s);
  }
}

static void feed_push_head(
    wired_wt_session* s, stream_slot* e, wired_span d, int fin) {
  usz prev = e->head_len;
  ssz nl;
  usz skip;
  head_append(e, d);
  nl = wired_span_find(wired_span_of(e->head, e->head_len), '\n');
  if (nl < 0) {
    if (fin) {
      e->state = ST_FREE; /* FIN before any newline: drop */
    }
    return;
  }
  skip = (usz)nl + 1 - prev; /* header bytes consumed from THIS chunk */
  push_start(s, e, (usz)nl + 1, wired_span_of(d.p + skip, d.n - skip), fin);
}

/* ST_PUSH_BODY and ST_BODY: stream the chunk straight to the download file
 * (never buffering the whole body in RAM). */
static void feed_save(
    wired_wt_session* s, stream_slot* e, wired_span d, int fin) {
  wired_fio_append(e->dest, d);
  if (fin) {
    e->state = ST_FREE;
    wti_note_saved(s);
  }
}

typedef void (*feed_fn)(wired_wt_session*, stream_slot*, wired_span, int);

static const feed_fn FEEDS[] = {
    feed_none,      /* ST_FREE */
    feed_get,       /* ST_GET */
    feed_push_head, /* ST_PUSH_HEAD */
    feed_save,      /* ST_PUSH_BODY */
    feed_save,      /* ST_BODY */
};

void wti_on_stream_data(
    void* ctx, wired_wt_session* s, u64 id, wired_span data, int fin) {
  stream_slot* e = stream_find(id);
  (void)ctx;
  if (!e) {
    e = stream_open(id);
  }
  if (!e) {
    return;
  }
  FEEDS[e->state](s, e, data, fin);
}
