#include "transport/stream/flow/flow/flow.h"

#include "common/bytes/util/num.h"

void flow_send_init(flow_send* f, u64 max_data) {
  f->sent     = 0;
  f->max_data = max_data;
}

u64 flow_send_avail(const flow_send* f) {
  return (f->max_data > f->sent) ? f->max_data - f->sent : 0;
}

int flow_send_record(flow_send* f, u64 n) {
  if (n > flow_send_avail(f)) return 0;
  f->sent += n;
  return 1;
}

void flow_send_update_max(flow_send* f, u64 max_data) {
  f->max_data = u64_max(f->max_data, max_data);
}

int flow_send_blocked(const flow_send* f, u64 want) {
  if (want == 0) return 0;          /* nothing to send, not blocked */
  return want > flow_send_avail(f); /* limit leaves too little room */
}

void flow_recv_init(flow_recv* f, u64 window) {
  f->consumed = 0;
  f->window   = window;
  f->max_data = window;
}

u64 flow_recv_consume(flow_recv* f, u64 n) {
  f->consumed += n;
  f->max_data = f->consumed + f->window; /* slide the credit forward */
  return f->max_data;
}
