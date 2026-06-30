#include "transport/stream/flow/flow/flow.h"

#include "common/bytes/util/num.h"

void quic_flow_send_init(quic_flow_send *f, u64 max_data) {
  f->sent     = 0;
  f->max_data = max_data;
}

u64 quic_flow_send_avail(const quic_flow_send *f) {
  return (f->max_data > f->sent) ? f->max_data - f->sent : 0;
}

int quic_flow_send_record(quic_flow_send *f, u64 n) {
  if (n > quic_flow_send_avail(f)) return 0;
  f->sent += n;
  return 1;
}

void quic_flow_send_update_max(quic_flow_send *f, u64 max_data) {
  f->max_data = quic_u64_max(f->max_data, max_data);
}

int quic_flow_send_blocked(const quic_flow_send *f, u64 want) {
  if (want == 0) return 0;               /* nothing to send, not blocked */
  return want > quic_flow_send_avail(f); /* limit leaves too little room */
}

void quic_flow_recv_init(quic_flow_recv *f, u64 window) {
  f->consumed = 0;
  f->window   = window;
  f->max_data = window;
}

u64 quic_flow_recv_consume(quic_flow_recv *f, u64 n) {
  f->consumed += n;
  f->max_data = f->consumed + f->window; /* slide the credit forward */
  return f->max_data;
}
