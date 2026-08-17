#ifndef QUIC_STREAM_BIDI_H
#define QUIC_STREAM_BIDI_H

#include "transport/stream/data/stream/stream.h"

/* RFC 9000 3.3: a bidirectional stream composes a send and a receive state
 * machine. The stream is fully closed once both halves reach a terminal
 * state. */

typedef struct {
  send_state send;
  recv_state recv;
} bidi;

void bidi_init(bidi* b);

int bidi_closed(const bidi* b);

#endif
