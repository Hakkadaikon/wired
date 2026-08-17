#include "transport/stream/flow/flow/stream_credit.h"

/* RFC 9000 4.6 */
void stream_credit_init(stream_credit* s, u64 max_streams) {
  s->max_streams = max_streams;
  s->count       = 0;
}

/* RFC 9000 4.6 */
int stream_credit_open(stream_credit* s) {
  if (s->count >= s->max_streams) return 0;
  s->count++;
  return 1;
}

/* RFC 9000 4.6 */
void stream_credit_grant(stream_credit* s, u64 new_max) {
  if (new_max > s->max_streams) s->max_streams = new_max;
}
