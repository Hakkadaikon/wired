#include "transport/stream/data/stream/stream_limit.h"

#include "transport/stream/data/stream/stream_id.h"

int stream_max_streams_ok(u64 max_streams) {
  return max_streams <= MAX_STREAMS_LIMIT;
}

int stream_max_id(const stream_kind* k, u64 max_streams, u64* out) {
  if (max_streams == 0) return 0; /* no stream permitted */
  if (!stream_max_streams_ok(max_streams)) return 0;
  *out = stream_id(k->is_server, k->is_uni, max_streams - 1);
  return 1;
}
