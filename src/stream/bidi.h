#ifndef QUIC_STREAM_BIDI_H
#define QUIC_STREAM_BIDI_H

#include "stream/stream.h"

/* RFC 9000 3.3: a bidirectional stream composes a send and a receive state
 * machine. The stream is fully closed once both halves reach a terminal
 * state. */

typedef struct {
    quic_send_state send;
    quic_recv_state recv;
} quic_bidi;

void quic_bidi_init(quic_bidi *b);

int quic_bidi_closed(const quic_bidi *b);

#endif
