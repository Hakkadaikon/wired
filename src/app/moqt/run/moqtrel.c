#include "app/moqt/run/moqtrel.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

_Static_assert(
    WIRED_MOQTREL_CAP >= 3 * WIRED_SRVLOOP_WT_BUF_CAP,
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

void moqtrel_reclaim(moqtrel_buf* b) {
  u64 low = b->tail;
  for (u32 i = 0; i < WIRED_MOQTREL_MAX_SUBS; i++)
    if (rel_sub_pins(&b->subs[i])) low = u64_min(low, b->subs[i].sent);
  b->head = low;
}
