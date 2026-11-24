#include "app/nostr/event/nostrev_impl.h"

static int nostrev_elem_room(const nostrev* ev, const nostrev_tag* t);
static int nostrev_elem(nostrev_lx* lx);
static int nostrev_tag_open(nostrev_lx* lx);
static int nostrev_tag1(nostrev_lx* lx);

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
