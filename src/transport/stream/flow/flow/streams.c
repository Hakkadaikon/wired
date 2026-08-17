#include "transport/stream/flow/flow/streams.h"

void streams_init(streams* s, u64 limit) {
  s->limit  = limit;
  s->opened = 0;
}

int streams_set_max(streams* s, u64 new_limit) {
  if (new_limit <= s->limit) return 0; /* MAX_STREAMS never lowers the limit */
  s->limit = new_limit;
  return 1;
}

int streams_may_open(const streams* s, u64 index) {
  return index < s->limit; /* index at or above the limit is a violation */
}

void streams_opened(streams* s) { s->opened++; }

void streams_observe(streams* s, u64 index) {
  u64 needed = index + 1; /* streams 0..index are now open */
  if (needed > s->opened) s->opened = needed;
}
