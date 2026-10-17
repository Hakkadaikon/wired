#include "app/http3/server/srvloop/body_window_impl.h"

static void bodywin_capq_shift(bodywin_capq* q, usz n);
static int  bodywin_capq_oversized(bodywin_capctx* k, u64 type, usz h, u64 len);
static int  bodywin_capq_whole(bodywin_capctx* k, u64 type, usz h, u64 len);
static int  bodywin_capq_pop(bodywin_capctx* k);
static int  bodywin_capq_drain(bodywin_capctx* k);
static int  bodywin_capq_feed(bodywin_capctx* k, wired_span chunk, usz* at);
static int  bodywin_cap_sink(void* ctx, wired_span chunk, int fin);
static int  bodywin_capq_partial(const bodywin_capq* q);

/* Drop the n buffered bytes in front of q. */
static void bodywin_capq_shift(bodywin_capq* q, usz n) {
  for (usz i = 0; i + n < q->n; i++) q->buf[i] = q->buf[i + n];
  q->n -= n;
}

/* A capsule whose h-byte header and len-byte value can never fit q:
 * announce it, then drop the value bytes held now and skip the rest. */
static int bodywin_capq_oversized(bodywin_capctx* k, u64 type, usz h, u64 len) {
  k->q->skip = len - (k->q->n - h);
  k->q->n    = 0;
  return k->fn(k->ctx, type, wired_span_of(0, 0)) != 0;
}

/* Hand over the whole capsule in front of q, or wait (2) for its value. */
static int bodywin_capq_whole(bodywin_capctx* k, u64 type, usz h, u64 len) {
  bodywin_capq* q = k->q;
  int           ok;
  if (len > q->n - h) return 2;
  ok = k->fn(k->ctx, type, wired_span_of(q->buf + h, (usz)len));
  bodywin_capq_shift(q, h + (usz)len);
  return ok != 0;
}

/* One capsule out of q: 1 handed over, 2 waiting for more bytes, 0 fn
 * said stop. */
static int bodywin_capq_pop(bodywin_capctx* k) {
  u64 type, len;
  usz h = bodywin_head(k->q->buf, k->q->n, &type, &len);
  if (!h) return 2;
  if (len > BODYWIN_CAPSULE_CAP - h)
    return bodywin_capq_oversized(k, type, h, len);
  return bodywin_capq_whole(k, type, h, len);
}

static int bodywin_capq_drain(bodywin_capctx* k) {
  int r;
  while ((r = bodywin_capq_pop(k)) == 1) {
  }
  return r != 0;
}

/* Take what fits of chunk from *at: skipped value bytes, or bytes appended
 * to q and every capsule they complete. 0 when fn said stop. */
static int bodywin_capq_feed(bodywin_capctx* k, wired_span chunk, usz* at) {
  bodywin_capq* q = k->q;
  usz           n = chunk.n - *at;
  if (q->skip) {
    n = (usz)u64_min(q->skip, n);
    q->skip -= n;
    *at += n;
    return 1;
  }
  n = (usz)u64_min(BODYWIN_CAPSULE_CAP - q->n, n);
  for (usz i = 0; i < n; i++) q->buf[q->n++] = chunk.p[(*at)++];
  return bodywin_capq_drain(k);
}

/* bodywin_pump sink: every DATA payload chunk is capsule bytes. */
static int bodywin_cap_sink(void* ctx, wired_span chunk, int fin) {
  usz at = 0;
  (void)fin;
  while (at < chunk.n)
    if (!bodywin_capq_feed(ctx, chunk, &at)) return 0;
  return 1;
}

static int bodywin_capq_partial(const bodywin_capq* q) {
  return q->n || q->skip;
}

int bodywin_capsules(
    bodywin* w, u8* buf, bodywin_capq* q, bodywin_capsule_fn fn, void* ctx) {
  bodywin_capctx k = {q, fn, ctx};
  /* RFC 9297 3.3: the stream ended inside a capsule. */
  if (bodywin_pump(w, buf, bodywin_cap_sink, &k) == BODYWIN_DONE &&
      bodywin_capq_partial(q))
    w->state = BODYWIN_FRAME_ERROR;
  return w->state;
}

u64 bodywin_credit_due(bodywin* w) {
  if (w->base <= w->granted) return 0;
  w->granted = w->base;
  return w->base + BODYWIN_CAP;
}
