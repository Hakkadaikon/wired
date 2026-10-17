#include "app/http3/core/h3/frame_impl.h"

static int frame_put_pair(h3frame_wcur* w, const u64* id, const u64* value);
static int take_pair_id(h3frame_rcur* r, h3_settings* s);
static int frame_take_pair(h3frame_rcur* r, h3_settings* s);
static int get_settings_head(h3frame_rcur* r, usz* end);
static usz settings_body_len(const h3_settings* s);
static int put_settings_pairs(h3frame_wcur* w, const h3_settings* s);
static int put_settings_head(h3frame_wcur* w, const h3_settings* s);
static int get_settings_pairs(h3frame_rcur* r, usz end, h3_settings* s);

/* Write one (Identifier Value) pair. Returns 1 ok, 0 on overflow. */
static int frame_put_pair(h3frame_wcur* w, const u64* id, const u64* value) {
  if (!varint_put(wired_mspan_of(w->buf, w->cap), &w->off, *id)) {
    return 0;
  }
  return varint_put(wired_mspan_of(w->buf, w->cap), &w->off, *value);
}

/* Read the Identifier into the next free slot, rejecting a full array. */
static int take_pair_id(h3frame_rcur* r, h3_settings* s) {
  if (s->n >= H3_SETTINGS_MAX) {
    return 0;
  }
  return varint_take(wired_span_of(r->buf, r->n), &r->off, &s->pairs[s->n].id);
}

/* Read one (Identifier Value) pair into the next free slot of s. Returns 1
 * ok, 0 if truncated or the fixed pair array is already full. */
static int frame_take_pair(h3frame_rcur* r, h3_settings* s) {
  if (!take_pair_id(r, s)) {
    return 0;
  }
  if (!varint_take(
          wired_span_of(r->buf, r->n), &r->off, &s->pairs[s->n].value)) {
    return 0;
  }
  s->n++;
  return 1;
}

/* Read the SETTINGS head, check the type, and bound the payload within
 * r->n. On success r->off points at the first pair and *end at the payload
 * end. */
static int get_settings_head(h3frame_rcur* r, usz* end) {
  u64 type, len;
  if (!h3frame_get_head(r, &type, &len)) {
    return 0;
  }
  if (type != H3_FRAME_SETTINGS) {
    return 0;
  }
  *end = r->off + (usz)len;
  return *end <= r->n;
}

/* Total byte length of the (Identifier Value) pairs. 0 if any varint is out
 * of range (so the caller rejects the whole frame). */
static usz settings_body_len(const h3_settings* s) {
  usz total = 0;
  for (usz i = 0; i < s->n; i++) {
    total += varint_len(s->pairs[i].id) + varint_len(s->pairs[i].value);
  }
  return total;
}

/* Append every (Identifier Value) pair after the head. Returns 1 ok, 0. */
static int put_settings_pairs(h3frame_wcur* w, const h3_settings* s) {
  int ok = 1;
  for (usz i = 0; i < s->n; i++) {
    if (!frame_put_pair(w, &s->pairs[i].id, &s->pairs[i].value)) {
      ok = 0;
    }
  }
  return ok;
}

/* Bound the pair count and write the SETTINGS head. Returns 1 ok, 0 bad. */
static int put_settings_head(h3frame_wcur* w, const h3_settings* s) {
  if (s->n > H3_SETTINGS_MAX) {
    return 0;
  }
  return h3frame_put_head(w, H3_FRAME_SETTINGS, settings_body_len(s));
}

usz h3_settings_put(u8* buf, usz cap, const h3_settings* s) {
  h3frame_wcur w = {buf, cap, 0};
  if (!put_settings_head(&w, s)) {
    return 0;
  }
  if (!put_settings_pairs(&w, s)) {
    return 0;
  }
  return w.off;
}

/* Read pairs until r->off reaches end. Returns 1 ok, 0 on
 * truncation/overflow. */
static int get_settings_pairs(h3frame_rcur* r, usz end, h3_settings* s) {
  s->n = 0;
  while (r->off < end) {
    if (!frame_take_pair(r, s)) {
      return 0;
    }
  }
  return 1;
}

usz h3_settings_get(const u8* buf, usz n, h3_settings* s) {
  h3frame_rcur r = {buf, n, 0};
  usz          end;
  if (!get_settings_head(&r, &end)) {
    return 0;
  }
  if (!get_settings_pairs(&r, end, s)) {
    return 0;
  }
  return r.off;
}
