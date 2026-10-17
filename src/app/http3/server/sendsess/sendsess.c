#include "app/http3/server/sendsess/sendsess_impl.h"

static int sendsess_free_slot(const wired_sendsess* s);
static int sent_slice_below(const wired_sent_slice* e, usz floor);
static usz sendsess_log_floor(const wired_sendsess* s, usz floor);
static usz sendsess_requeue_floor(const wired_sendsess* s, usz floor);

void wired_sendsess_arm(
    wired_sendsess* s, const u8* stream, usz len, usz chunk) {
  wired_sendq_init(&s->q, stream, len, chunk);
  s->active             = 1;
  s->requeue_n          = 0;
  s->largest_acked      = 0;
  s->has_acked          = 0;
  s->pto_count          = 0;
  s->stream_base_offset = 0;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    s->log[i].inflight = 0;
  }
}

void wired_sendsess_extend(wired_sendsess* s, usz added) {
  s->q.len += added;
  s->active = 1;
}

void wired_sendsess_set_base_offset(wired_sendsess* s, u64 base_offset) {
  s->stream_base_offset = base_offset;
}

u64 wired_sendsess_stream_offset(
    const wired_sendsess* s, const wired_sendq_slice* sl) {
  return s->stream_base_offset + sl->offset;
}

usz wired_sendsess_inflight(const wired_sendsess* s) {
  usz n = 0;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    n += (usz)(s->log[i].inflight != 0);
  }
  return n;
}

int wired_sendsess_take(wired_sendsess* s, wired_sendq_slice* out) {
  if (s->requeue_n) {
    *out = s->requeue[--s->requeue_n];
    return 1;
  }
  return wired_sendq_next(&s->q, out);
}

/* First free log slot, or -1 when every slot is in flight. */
static int sendsess_free_slot(const wired_sendsess* s) {
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    if (!s->log[i].inflight) {
      return (int)i;
    }
  }
  return -1;
}

int wired_sendsess_sent(
    wired_sendsess* s, const wired_sendq_slice* sl, u64 pn, u64 now_ms) {
  int i = sendsess_free_slot(s);
  if (i < 0) {
    return 0;
  }
  s->log[i].pn       = pn;
  s->log[i].sl       = *sl;
  s->log[i].inflight = 1;
  s->log[i].sent_ms  = now_ms;
  return 1;
}

/* Room is structural: a slice taken from the requeue freed the very slot it
 * goes back into, and a slice taken from the sendq implies the requeue was
 * empty (wired_sendsess_take drains the requeue first). The bound check
 * keeps the function total anyway. */
void wired_sendsess_untake(wired_sendsess* s, const wired_sendq_slice* sl) {
  if (s->requeue_n < WIRED_SENDSESS_LOG) {
    s->requeue[s->requeue_n++] = *sl;
  }
}

usz wired_sendsess_inflight_bytes(const wired_sendsess* s) {
  usz n = 0;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    if (s->log[i].inflight) {
      n += s->log[i].sl.len;
    }
  }
  return n;
}

/* 1 if in-flight log entry e pins a lower offset than floor. */
static int sent_slice_below(const wired_sent_slice* e, usz floor) {
  return e->inflight && e->sl.offset < floor;
}

static usz sendsess_log_floor(const wired_sendsess* s, usz floor) {
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    if (sent_slice_below(&s->log[i], floor)) {
      floor = s->log[i].sl.offset;
    }
  }
  return floor;
}

static usz sendsess_requeue_floor(const wired_sendsess* s, usz floor) {
  for (usz i = 0; i < s->requeue_n; i++) {
    if (s->requeue[i].offset < floor) {
      floor = s->requeue[i].offset;
    }
  }
  return floor;
}

usz wired_sendsess_unacked_floor(const wired_sendsess* s) {
  return sendsess_requeue_floor(s, sendsess_log_floor(s, s->q.cur));
}
