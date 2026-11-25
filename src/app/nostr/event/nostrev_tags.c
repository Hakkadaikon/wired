#include "app/nostr/event/nostrev_impl.h"
#include "common/bytes/text/text.h"

static int        nostrev_elem_room(const nostrev* ev, const nostrev_tag* t);
static int        nostrev_elem(nostrev_lx* lx);
static int        nostrev_tag_open(nostrev_lx* lx);
static int        nostrev_tag1(nostrev_lx* lx);
static wired_span nostrev_str_at(const nostrev* ev, u32 e);
static int        nostrev_tag_named(
    const nostrev* ev, const nostrev_tag* t, const char* name, u32 k);

static int nostrev_elem_room(const nostrev* ev, const nostrev_tag* t) {
  return ev->nelems < NOSTREV_MAX_ELEMS && t->n < NOSTREV_MAX_TAG_ELEMS;
}

/* One tag string, appended to the tag in progress (tag[ntags]). */
static int nostrev_elem(nostrev_lx* lx) {
  nostrev*     ev = lx->ev;
  nostrev_tag* t  = &ev->tag[ev->ntags];
  nostrev_str* s  = &ev->elem[ev->nelems];
  if (!nostrev_elem_room(ev, t) || !nostrev_lex_str(lx, s)) {
    return 0;
  }
  t->n++;
  ev->nelems++;
  return s->len <= NOSTREV_MAX_TAG_STR;
}

static int nostrev_tag_open(nostrev_lx* lx) {
  return lx->ev->ntags < NOSTREV_MAX_TAGS && nostrev_take(lx) == '[';
}

/* NIP-01: each tag is an array of one or more strings. */
static int nostrev_tag1(nostrev_lx* lx) {
  nostrev* ev = lx->ev;
  if (!nostrev_tag_open(lx)) {
    return 0;
  }
  ev->tag[ev->ntags].first = (u16)ev->nelems;
  if (!nostrev_list(lx, ']', nostrev_elem)) {
    return 0;
  }
  return ev->tag[ev->ntags++].n > 0;
}

int nostrev_tags(nostrev_lx* lx) {
  return nostrev_take(lx) == '[' && nostrev_list(lx, ']', nostrev_tag1);
}

static wired_span nostrev_str_at(const nostrev* ev, u32 e) {
  return wired_span_of(ev->buf + ev->elem[e].off, ev->elem[e].len);
}

static int nostrev_tag_named(
    const nostrev* ev, const nostrev_tag* t, const char* name, u32 k) {
  return t->n > k && wired_span_eq_cstr(nostrev_str_at(ev, t->first), name);
}

wired_span nostrev_tag_value(const nostrev* ev, const char* name, u32 k) {
  for (u32 i = 0; i < ev->ntags; i++) {
    if (nostrev_tag_named(ev, &ev->tag[i], name, k)) {
      return nostrev_str_at(ev, ev->tag[i].first + k);
    }
  }
  return wired_span_of(0, 0);
}

usz nostrev_tag_count(const nostrev* ev, const char* name) {
  usz hits = 0;
  for (u32 i = 0; i < ev->ntags; i++) {
    hits += (usz)nostrev_tag_named(ev, &ev->tag[i], name, 0);
  }
  return hits;
}
