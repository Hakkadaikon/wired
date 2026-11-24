#include "app/nostr/nip98/nip98_impl.h"
#include "common/bytes/util/bytes.h"

static wired_span nip98_elem(const nostrev* ev, u32 k);
static int        nip98_named(
    const nostrev* ev, const nostrev_tag* t, wired_span name);
static usz nip98_find(
    const nostrev* ev, wired_span nm, const nostrev_tag** last);
static int nip98_value_is(
    const nostrev* ev, const nostrev_tag* t, wired_span want);

static wired_span nip98_elem(const nostrev* ev, u32 k) {
  return wired_span_of(ev->buf + ev->elem[k].off, ev->elem[k].len);
}

/* nostrev_parse guarantees every tag has at least one string. */
static int nip98_named(
    const nostrev* ev, const nostrev_tag* t, wired_span name) {
  return bytes_span_eq(nip98_elem(ev, t->first), name);
}

/* Number of tags named nm; *last = the last of them. */
static usz nip98_find(
    const nostrev* ev, wired_span nm, const nostrev_tag** last) {
  usz hits = 0;
  for (u32 i = 0; i < ev->ntags; i++) {
    int m = nip98_named(ev, &ev->tag[i], nm);
    hits += (usz)m;
    *last = m ? &ev->tag[i] : *last;
  }
  return hits;
}

/* The tag has a value (a second string) and it equals want. */
static int nip98_value_is(
    const nostrev* ev, const nostrev_tag* t, wired_span want) {
  return t->n >= 2 && bytes_span_eq(nip98_elem(ev, t->first + 1u), want);
}

/* Exactly one tag named name, with a value equal to want: two "u" tags
 * would be read differently by different verifiers. */
int nip98_tag_is(const nostrev* ev, const char* name, wired_span want) {
  const nostrev_tag* t = 0;
  usz                hits =
      nip98_find(ev, wired_span_of((const u8*)name, wired_cstr_len(name)), &t);
  return hits == 1 && nip98_value_is(ev, t, want);
}
