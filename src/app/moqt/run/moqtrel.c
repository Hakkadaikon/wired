#include "app/moqt/run/moqtrel.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

_Static_assert(
    WIRED_MOQTREL_CAP >= (u64)3 * WIRED_SRVLOOP_WT_BUF_CAP,
    "ring absorbs the held publisher window");
_Static_assert(
    WIRED_MOQTREL_ROUND_MAX <= WIRED_SRVLOOP_WT_BUF_CAP / 2,
    "one round fits the release watermark");

/* Unreclaimed bytes currently occupying the ring. */
static u64 rel_used(const moqtrel_buf* b) { return b->tail - b->head; }

/* Rewritable bytes left before append would overrun head. */
static u64 rel_free(const moqtrel_buf* b) {
  return WIRED_MOQTREL_CAP - rel_used(b);
}

/* 1 while cursor s still pins head (live and not given up on). */
static int rel_sub_pins(const moqtrel_sub* s) { return s->active && !s->shed; }

/* 1 while cursor s still needs delivery work before the ring can close. */
static int rel_sub_open(const moqtrel_sub* s) {
  return rel_sub_pins(s) && !s->fin_done;
}

/* Copy src at tail, splitting at the physical ring end; caller checked fit. */
static void rel_copy_in(moqtrel_buf* b, wired_span src) {
  usz pos   = (usz)(b->tail % WIRED_MOQTREL_CAP);
  usz first = (usz)u64_min(src.n, WIRED_MOQTREL_CAP - pos);
  bytes_memcpy(b->buf + pos, src.p, first);
  bytes_memcpy(b->buf, src.p + first, src.n - first);
  b->tail += src.n;
}

void moqtrel_reset(moqtrel_buf* b) { bytes_memset(b, 0, sizeof(*b)); }

int moqtrel_append(moqtrel_buf* b, wired_span src) {
  if (src.n > rel_free(b)) return 0;
  rel_copy_in(b, src);
  return 1;
}

wired_span moqtrel_next_round(const moqtrel_buf* b, u32 sub) {
  const moqtrel_sub* s   = &b->subs[sub];
  u64                pos = s->sent % WIRED_MOQTREL_CAP;
  u64                n   = u64_min(b->tail - s->sent, WIRED_MOQTREL_ROUND_MAX);
  n                      = u64_min(n, WIRED_MOQTREL_CAP - pos);
  return wired_span_of(b->buf + pos, (usz)n);
}

void moqtrel_note_sent(moqtrel_buf* b, u32 sub, usz n, u64 now_ms) {
  b->subs[sub].sent += n;
  b->subs[sub].last_ok_ms = now_ms;
}

/* 1 iff the newest mark takes this append: same ms, or no mark free. */
static int rel_mark_merges(const moqtrel_buf* b, u64 now_ms) {
  return b->marks == WIRED_MOQTREL_MARKS ||
         (b->marks && b->mark_ms[b->marks - 1] == now_ms);
}

/* A merge keeps the newest mark's time: merged bytes read as old as it,
 * never younger than they are. */
void moqtrel_mark(moqtrel_buf* b, u64 now_ms) {
  if (!rel_mark_merges(b, now_ms)) b->mark_ms[b->marks++] = now_ms;
  b->mark_end[b->marks - 1] = b->tail;
}

u64 moqtrel_age_ms(const moqtrel_buf* b, u32 sub, u64 now_ms) {
  u64 at = b->subs[sub].sent;
  for (u32 k = 0; k < b->marks; k++)
    if (b->mark_end[k] > at) return now_ms - b->mark_ms[k];
  return 0;
}

/* Leading marks wholly below head. */
static u32 rel_marks_spent(const moqtrel_buf* b) {
  u32 d = 0;
  while (d < b->marks && b->mark_end[d] <= b->head) d++;
  return d;
}

static void rel_marks_trim(moqtrel_buf* b) {
  u32 d = rel_marks_spent(b);
  for (u32 k = d; k < b->marks; k++) {
    b->mark_end[k - d] = b->mark_end[k];
    b->mark_ms[k - d]  = b->mark_ms[k];
  }
  b->marks -= d;
}

void moqtrel_reclaim(moqtrel_buf* b) {
  u64 low = b->tail;
  for (u32 i = 0; i < WIRED_MOQTREL_MAX_SUBS; i++)
    if (rel_sub_pins(&b->subs[i])) low = u64_min(low, b->subs[i].sent);
  b->head = low;
  rel_marks_trim(b);
}

int moqtrel_should_hold(const moqtrel_buf* b) {
  return rel_free(b) < (u64)2 * WIRED_SRVLOOP_WT_BUF_CAP && !b->held;
}

int moqtrel_should_release(const moqtrel_buf* b) {
  return b->held && rel_used(b) <= WIRED_SRVLOOP_WT_BUF_CAP / 2;
}

int moqtrel_stalled(const moqtrel_buf* b, u32 sub, u64 now_ms) {
  const moqtrel_sub* s = &b->subs[sub];
  if (!rel_sub_pins(s) || s->sent >= b->tail) return 0;
  return now_ms - s->last_ok_ms > WIRED_MOQTREL_STALL_MS;
}

int moqtrel_all_done(const moqtrel_buf* b) {
  for (u32 i = 0; i < WIRED_MOQTREL_MAX_SUBS; i++)
    if (rel_sub_open(&b->subs[i])) return 0;
  return 1;
}

int moqtrel_awaits_sub(const moqtrel_buf* b, u64 now_ms) {
  return !b->fin_seen && b->head == 0 &&
         now_ms - b->bound_ms <= WIRED_MOQTREL_STALL_MS;
}
