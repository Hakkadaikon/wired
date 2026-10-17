#include "app/http3/server/srvloop/srvloop_impl.h"

static int slot_matches(const wired_srvloop_stream_slot* slot, u64 stream_id);
static int pending_priority_matches(
    const wired_srvloop* l, usz i, u64 stream_id);
static void srvloop_closed_shift1(wired_srvloop_closed* w);

/* 1 if slot is claimed and reassembling stream_id. */
static int slot_matches(const wired_srvloop_stream_slot* slot, u64 stream_id) {
  return slot->in_use && slot->stream_id == stream_id;
}

/* RFC 9000 2.2: find the slot already reassembling stream_id.
 * @return the slot index, or -1 if this stream has no slot yet. */
int srvloop_stream_slot_find(const wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    if (slot_matches(&l->streams[i], stream_id)) return (int)i;
  return -1;
}

/* 1 if pending_priority[] slot i is buffered for stream_id. */
static int pending_priority_matches(
    const wired_srvloop* l, usz i, u64 stream_id) {
  return l->pending_priority[i].in_use &&
         l->pending_priority[i].stream_id == stream_id;
}

/* RFC 9218 10 / 9218-010: the pending_priority[] slot index buffered for
 * stream_id, or -1 if none is waiting. */
int srvloop_pending_priority_find(const wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_PENDING_PRIORITY; i++)
    if (pending_priority_matches(l, i, stream_id)) return (int)i;
  return -1;
}

/* RFC 9218 10 / 9218-010: a stream just claimed at slot i adopts any priority
 * that was buffered for its id ahead of it opening, consuming that pending
 * entry; a stream with nothing buffered keeps its RFC 9218 4.1 default. */
void srvloop_pending_priority_consume(wired_srvloop* l, usz i) {
  int p = srvloop_pending_priority_find(l, l->streams[i].stream_id);
  if (p < 0) return;
  l->streams[i].priority        = l->pending_priority[p].priority;
  l->pending_priority[p].in_use = 0;
}

/* Shift the closed-stream window up k whole words (64 indexes each) in one
 * pass: a k of 16 or more clears it, however far it jumps. */
void srvloop_closed_shift64(wired_srvloop_closed* w, u64 k) {
  for (usz i = 0; i < 16; i++) w->bm[i] = k < 16 - i ? w->bm[i + k] : 0;
  w->floor += 64 * k;
}

/* Shift the closed-stream window down one index (one bit, with carry). */
static void srvloop_closed_shift1(wired_srvloop_closed* w) {
  for (usz i = 0; i < 16; i++) {
    u64 carry = i + 1 < 16 ? w->bm[i + 1] << 63 : 0;
    w->bm[i]  = (w->bm[i] >> 1) | carry;
  }
  w->floor += 1;
}

/* Advance floor over the contiguous closed prefix, keeping the window
 * anchored just past the lowest still-open stream index. */
void srvloop_closed_advance(wired_srvloop_closed* w) {
  while (w->bm[0] == ~(u64)0) srvloop_closed_shift64(w, 1);
  while (w->bm[0] & 1) srvloop_closed_shift1(w);
}
