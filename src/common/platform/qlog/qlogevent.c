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
  usz n = quic_cstr_len(s);
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

usz wired_qlogevent_packet_sent(
    char* out, usz outcap, u64 time, u64 pn, usz bytes) {
  qev_w w = {out, outcap, 0};
  qev_put_str(&w, "{\"time\":");
  qev_put_u64(&w, time);
  qev_put_str(&w, ",\"name\":\"packet_sent\",\"pn\":");
  qev_put_u64(&w, pn);
  qev_put_str(&w, ",\"bytes\":");
  qev_put_u64(&w, bytes);
  qev_put_str(&w, "}");
  return qev_finish(&w);
}

usz wired_qlogevent_packet_received(
    char* out, usz outcap, u64 time, u64 pn, usz bytes) {
  qev_w w = {out, outcap, 0};
  qev_put_str(&w, "{\"time\":");
  qev_put_u64(&w, time);
  qev_put_str(&w, ",\"name\":\"packet_received\",\"pn\":");
  qev_put_u64(&w, pn);
  qev_put_str(&w, ",\"bytes\":");
  qev_put_u64(&w, bytes);
  qev_put_str(&w, "}");
  return qev_finish(&w);
}

usz wired_qlogevent_packet_lost(char* out, usz outcap, u64 time, u64 pn) {
  qev_w w = {out, outcap, 0};
  qev_put_str(&w, "{\"time\":");
  qev_put_u64(&w, time);
  qev_put_str(&w, ",\"name\":\"packet_lost\",\"pn\":");
  qev_put_u64(&w, pn);
  qev_put_str(&w, "}");
  return qev_finish(&w);
}

usz wired_qlogevent_conn_state(
    char* out, usz outcap, u64 time, const char* state) {
  qev_w w = {out, outcap, 0};
  qev_put_str(&w, "{\"time\":");
  qev_put_u64(&w, time);
  qev_put_str(&w, ",\"name\":\"connection_state_updated\",\"state\":\"");
  qev_put_str(&w, state);
  qev_put_str(&w, "\"}");
  return qev_finish(&w);
}
