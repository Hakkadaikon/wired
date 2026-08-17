#include "app/webtransport/session/session/session.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

/* clang-format off */
/* State transition table, indexed [event][current state]. Not used as a
 * runtime dispatch (the transitions are simple enough to guard inline
 * below) -- kept here as a single place that documents every case so
 * completeness is visible at a glance:
 *
 *              unest      established  draining     closed
 * establish -> established  (no-op)     (no-op)      (no-op)
 * drain     -> (no-op)      draining    (no-op)      (no-op)
 * close     -> closed       closed      closed       (no-op)
 */
/* clang-format on */

static void stream_slot_clear(wired_wt_buffered_stream* slot) {
  slot->in_use    = 0;
  slot->stream_id = 0;
}

static void datagram_slot_clear(wired_wt_buffered_datagram* slot) {
  slot->in_use = 0;
  slot->len    = 0;
}

void wired_wt_session_init(wired_wt_session* s, u64 connect_stream_id) {
  s->state             = WIRED_WT_UNESTABLISHED;
  s->connect_stream_id = connect_stream_id;
  for (usz i = 0; i < WIRED_WT_MAX_BUFFERED_STREAMS; i++)
    stream_slot_clear(&s->streams[i]);
  for (usz i = 0; i < WIRED_WT_MAX_BUFFERED_DATAGRAMS; i++)
    datagram_slot_clear(&s->datagrams[i]);
  s->max_streams_bidi    = 0;
  s->max_streams_uni     = 0;
  s->opened_streams_bidi = 0;
  s->opened_streams_uni  = 0;
  s->max_data            = 0;
  s->sent_data           = 0;
}

int wired_wt_session_establish(wired_wt_session* s) {
  if (s->state != WIRED_WT_UNESTABLISHED) return 0;
  s->state = WIRED_WT_ESTABLISHED;
  return 1;
}

int wired_wt_session_drain(wired_wt_session* s) {
  if (s->state != WIRED_WT_ESTABLISHED) return 0;
  s->state = WIRED_WT_DRAINING;
  return 1;
}

int wired_wt_session_close(wired_wt_session* s) {
  if (s->state == WIRED_WT_CLOSED) return 0;
  s->state = WIRED_WT_CLOSED;
  return 1;
}

/* 1 iff streams/datagrams should associate directly rather than buffer:
 * established and draining both skip buffering (only unestablished
 * buffers). */
static int session_associates_directly(const wired_wt_session* s) {
  return s->state != WIRED_WT_UNESTABLISHED;
}

static wired_wt_buffered_stream* stream_free_slot(wired_wt_session* s) {
  for (usz i = 0; i < WIRED_WT_MAX_BUFFERED_STREAMS; i++)
    if (!s->streams[i].in_use) return &s->streams[i];
  return 0;
}

int wired_wt_session_offer_stream(wired_wt_session* s, u64 stream_id) {
  wired_wt_buffered_stream* slot;
  if (session_associates_directly(s)) return 1;
  slot = stream_free_slot(s);
  if (!slot) return 0;
  slot->in_use    = 1;
  slot->stream_id = stream_id;
  return 1;
}

static wired_wt_buffered_datagram* datagram_free_slot(wired_wt_session* s) {
  for (usz i = 0; i < WIRED_WT_MAX_BUFFERED_DATAGRAMS; i++)
    if (!s->datagrams[i].in_use) return &s->datagrams[i];
  return 0;
}

static void datagram_slot_fill(
    wired_wt_buffered_datagram* slot, wired_span data) {
  usz n        = u64_min(data.n, WIRED_WT_BUFFERED_DATAGRAM_CAP);
  slot->in_use = 1;
  slot->len    = n;
  bytes_memcpy(slot->data, data.p, n);
}

int wired_wt_session_offer_datagram(wired_wt_session* s, wired_span data) {
  wired_wt_buffered_datagram* slot;
  if (session_associates_directly(s)) return 1;
  slot = datagram_free_slot(s);
  if (!slot) return 0;
  datagram_slot_fill(slot, data);
  return 1;
}

/* Reads the bidi or uni WT_MAX_STREAMS limit, so every direction-aware
 * stream-limit function shares one branch instead of repeating the
 * bidi ? ... : ... choice (keeps each caller at CCN<=3). */
static u64 stream_limit_get(const wired_wt_session* s, int bidi) {
  return bidi ? s->max_streams_bidi : s->max_streams_uni;
}

/* Same read for the cumulative opened-stream counter. */
static u64 stream_opened_get(const wired_wt_session* s, int bidi) {
  return bidi ? s->opened_streams_bidi : s->opened_streams_uni;
}

int wired_wt_session_set_max_streams(
    wired_wt_session* s, int bidi, u64 max_streams) {
  if (max_streams < stream_limit_get(s, bidi)) return 0;
  if (bidi)
    s->max_streams_bidi = max_streams;
  else
    s->max_streams_uni = max_streams;
  return 1;
}

int wired_wt_session_stream_open_allowed(const wired_wt_session* s, int bidi) {
  u64 limit  = stream_limit_get(s, bidi);
  u64 opened = stream_opened_get(s, bidi);
  return limit == 0 || opened < limit;
}

void wired_wt_session_note_stream_opened(wired_wt_session* s, int bidi) {
  if (bidi)
    s->opened_streams_bidi += 1;
  else
    s->opened_streams_uni += 1;
}

int wired_wt_session_set_max_data(wired_wt_session* s, u64 max_data) {
  if (max_data < s->max_data) return 0;
  s->max_data = max_data;
  return 1;
}

int wired_wt_session_data_send_allowed(const wired_wt_session* s, usz len) {
  return s->max_data == 0 || s->sent_data + len <= s->max_data;
}

void wired_wt_session_note_data_sent(wired_wt_session* s, usz len) {
  s->sent_data += len;
}
