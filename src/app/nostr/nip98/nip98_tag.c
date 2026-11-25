#include "app/nostr/nip98/nip98_impl.h"
#include "common/bytes/util/bytes.h"

/* Exactly one tag named name, with a value equal to want: two "u" tags
 * would be read differently by different verifiers. */
int nip98_tag_is(const nostrev* ev, const char* name, wired_span want) {
  wired_span v = nostrev_tag_value(ev, name, 1);
  return nostrev_tag_count(ev, name) == 1 && v.p && bytes_span_eq(v, want);
}
