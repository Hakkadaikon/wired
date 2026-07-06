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

static void datagram_slot_fill(wired_wt_buffered_datagram* slot, quic_span data) {
  usz n = quic_u64_min(data.n, WIRED_WT_BUFFERED_DATAGRAM_CAP);
  slot->in_use = 1;
  slot->len    = n;
  quic_memcpy(slot->data, data.p, n);
}

int wired_wt_session_offer_datagram(wired_wt_session* s, quic_span data) {
  wired_wt_buffered_datagram* slot;
  if (session_associates_directly(s)) return 1;
  slot = datagram_free_slot(s);
  if (!slot) return 0;
  datagram_slot_fill(slot, data);
  return 1;
}
