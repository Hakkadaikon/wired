#include "app/http3/server/srvloop/srvloop_impl.h"

static int  pending_priority_free_slot(const wired_srvloop* l);
static void pending_priority_set(
    wired_srvloop* l, u64 stream_id, const h3_priority* p);
static int wt_slot_matches(
    const wired_srvloop_wt_stream_slot* slot, u64 stream_id);

/* The first free pending_priority[] slot, or -1 if the table is full. */
static int pending_priority_free_slot(const wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_PENDING_PRIORITY; i++)
    if (!l->pending_priority[i].in_use) return (int)i;
  return -1;
}

/* RFC 9218 10 / 9218-010: buffer priority for stream_id in a free
 * pending_priority[] slot, overwriting stream_id's own existing entry if it
 * already has one (only the newest update for a not-yet-open stream
 * matters). A full table with no existing entry for stream_id drops the
 * update, same truncate-on-overflow policy family as this file's other fixed
 * tables. */
static void pending_priority_set(
    wired_srvloop* l, u64 stream_id, const h3_priority* p) {
  int i = srvloop_pending_priority_find(l, stream_id);
  if (i < 0) i = pending_priority_free_slot(l);
  if (i < 0) return;
  l->pending_priority[i].in_use    = 1;
  l->pending_priority[i].stream_id = stream_id;
  l->pending_priority[i].priority  = *p;
}

void wired_srvloop_priority_apply(
    wired_srvloop* l, u64 stream_id, const h3_priority* p) {
  int i = srvloop_stream_slot_find(l, stream_id);
  if (i >= 0)
    l->streams[i].priority = *p;
  else
    pending_priority_set(l, stream_id, p);
}

/* RFC 9218 10: a response scheduler (srvrun.c) needs stream_id's current
 * priority to order its send passes, without itself claiming/allocating a
 * streams[] slot (that stays wired_srvloop_slot_for's job, called only from
 * the receive path) -- this is the read-only counterpart. */
int wired_srvloop_priority_of(
    const wired_srvloop* l, u64 stream_id, h3_priority* out) {
  int i = srvloop_stream_slot_find(l, stream_id);
  if (i < 0) return 0;
  *out = l->streams[i].priority;
  return 1;
}

/* 1 if wt slot is claimed and reassembling stream_id. */
static int wt_slot_matches(
    const wired_srvloop_wt_stream_slot* slot, u64 stream_id) {
  return slot->in_use && slot->stream_id == stream_id;
}

/* draft-ietf-webtrans-http3-15 4.3: find the wt_streams slot already
 * reassembling stream_id.
 * @return the slot index, or -1 if this stream has no slot yet. */
int wired_srvloop_wt_slot_find(const wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    if (wt_slot_matches(&l->wt_streams[i], stream_id)) return (int)i;
  return -1;
}
