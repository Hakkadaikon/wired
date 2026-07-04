#include "transport/stream/data/stream/bidi.h"

void quic_bidi_init(quic_bidi* b) {
  b->send = QUIC_SEND_READY;
  b->recv = QUIC_RECV_RECV;
}

/* The send half is terminal once all data or the reset is acknowledged. */
static int send_terminal(quic_send_state s) {
  return s == QUIC_SEND_DATA_RECVD || s == QUIC_SEND_RESET_RECVD;
}

/* The receive half is terminal once all data or the reset has been read. */
static int recv_terminal(quic_recv_state s) {
  return s == QUIC_RECV_DATA_READ || s == QUIC_RECV_RESET_READ;
}

int quic_bidi_closed(const quic_bidi* b) {
  return send_terminal(b->send) && recv_terminal(b->recv);
}
