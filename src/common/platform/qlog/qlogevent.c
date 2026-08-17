#include "common/platform/qlog/qlogevent.h"

#include "common/bytes/util/bytes.h"
#include "common/platform/debug/debug.h"

/* Write cursor over a fixed out/cap pair. Once overflowed, at is pinned to
 * cap+1 ("poisoned") so every subsequent put_* becomes a no-op; callers chain
 * puts without an if-guard per call, keeping each build_* function CCN <= 3. */
typedef struct {
  char* out;
  usz   cap;
  usz   at;
} qev_w;

static int qev_overflowed(const qev_w* w) { return w->at > w->cap; }

/* Poisons w and returns 0 (not reserved) when n more bytes would not fit;
 * otherwise returns 1. Folds the overflowed-check and the room-check into one
 * predicate so callers stay a single `if`. */
static int qev_reserve(qev_w* w, usz n) {
  if (qev_overflowed(w) || w->at + n > w->cap) {
    w->at = w->cap + 1;
    return 0;
  }
  return 1;
}

static void qev_copy(qev_w* w, const char* s, usz n) {
  for (usz i = 0; i < n; i++) w->out[w->at++] = s[i];
}

static void qev_put_str(qev_w* w, const char* s) {
  usz n = wired_cstr_len(s);
  if (!qev_reserve(w, n)) return;
  qev_copy(w, s, n);
}

/* Decimal digit count of v (at least 1, for v == 0). */
static usz qev_digits(u64 v) {
  usz n = 1;
  while (v >= 10) {
    v /= 10;
    n++;
  }
  return n;
}

static void qev_put_u64(qev_w* w, u64 v) {
  usz n = qev_digits(v);
  if (!qev_reserve(w, n)) return;
  wired_fmt_u64(w->out, &w->at, &(wired_fmt_u64_in){v, n});
}

/* 0 on overflow, else the byte count written. */
static usz qev_finish(const qev_w* w) { return qev_overflowed(w) ? 0 : w->at; }

/* Every record opens the same way: time, then the connection attribution
 * (qlogevent.h's group doc -- one shared qlog file, many connections). */
static void qev_put_head(qev_w* w, u64 time, u64 group) {
  qev_put_str(w, "{\"time\":");
  qev_put_u64(w, time);
  qev_put_str(w, ",\"group_id\":");
  qev_put_u64(w, group);
}

usz wired_qlogevent_packet_sent(
    char* out, usz outcap, u64 time, u64 group, u64 pn, usz bytes) {
  qev_w w = {out, outcap, 0};
  qev_put_head(&w, time, group);
  qev_put_str(&w, ",\"name\":\"packet_sent\",\"pn\":");
  qev_put_u64(&w, pn);
  qev_put_str(&w, ",\"bytes\":");
  qev_put_u64(&w, bytes);
  qev_put_str(&w, "}");
  return qev_finish(&w);
}

usz wired_qlogevent_packet_received(
    char* out, usz outcap, u64 time, u64 group, u64 pn, usz bytes) {
  qev_w w = {out, outcap, 0};
  qev_put_head(&w, time, group);
  qev_put_str(&w, ",\"name\":\"packet_received\",\"pn\":");
  qev_put_u64(&w, pn);
  qev_put_str(&w, ",\"bytes\":");
  qev_put_u64(&w, bytes);
  qev_put_str(&w, "}");
  return qev_finish(&w);
}

usz wired_qlogevent_packet_lost(
    char* out, usz outcap, u64 time, u64 group, u64 pn) {
  qev_w w = {out, outcap, 0};
  qev_put_head(&w, time, group);
  qev_put_str(&w, ",\"name\":\"packet_lost\",\"pn\":");
  qev_put_u64(&w, pn);
  qev_put_str(&w, "}");
  return qev_finish(&w);
}

usz wired_qlogevent_conn_state(
    char* out, usz outcap, u64 time, u64 group, const char* state) {
  qev_w w = {out, outcap, 0};
  qev_put_head(&w, time, group);
  qev_put_str(&w, ",\"name\":\"connection_state_updated\",\"state\":\"");
  qev_put_str(&w, state);
  qev_put_str(&w, "\"}");
  return qev_finish(&w);
}

/* One key:value pair with a leading comma (every metrics field follows the
 * record's opening time field, so the comma is unconditional). */
static void qev_put_field(qev_w* w, const char* key, u64 v) {
  qev_put_str(w, ",\"");
  qev_put_str(w, key);
  qev_put_str(w, "\":");
  qev_put_u64(w, v);
}

usz wired_qlogevent_metrics(
    char*                             out,
    usz                               outcap,
    u64                               time,
    u64                               group,
    const wired_qlogevent_metrics_in* m) {
  qev_w w = {out, outcap, 0};
  qev_put_head(&w, time, group);
  qev_put_str(&w, ",\"name\":\"recovery:metrics_updated\"");
  qev_put_field(&w, "smoothed_rtt", m->smoothed_rtt);
  qev_put_field(&w, "cwnd", m->cwnd);
  qev_put_field(&w, "bytes_in_flight", m->bytes_in_flight);
  qev_put_field(&w, "wtsend_ok", m->wtsend_ok);
  qev_put_field(&w, "wtsend_busy", m->wtsend_busy);
  qev_put_field(&w, "wtsend_flow", m->wtsend_flow);
  qev_put_field(&w, "wtwin_drop", m->wtwin_drop);
  qev_put_field(&w, "streams_blocked", m->streams_blocked);
  qev_put_str(&w, "}");
  return qev_finish(&w);
}

usz wired_qlogevent_stream_frame(
    char*                                  out,
    usz                                    outcap,
    u64                                    time,
    u64                                    group,
    const char*                            name,
    const wired_qlogevent_stream_frame_in* f) {
  qev_w w = {out, outcap, 0};
  qev_put_head(&w, time, group);
  qev_put_str(&w, ",\"name\":\"");
  qev_put_str(&w, name);
  qev_put_str(&w, "\"");
  qev_put_field(&w, "stream_id", f->stream_id);
  qev_put_field(&w, "offset", f->offset);
  qev_put_field(&w, "length", f->length);
  qev_put_field(&w, "fin", f->fin);
  qev_put_field(&w, "pn", f->pn);
  qev_put_str(&w, "}");
  return qev_finish(&w);
}
