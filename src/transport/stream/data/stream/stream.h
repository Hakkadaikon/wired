#ifndef QUIC_STREAM_STREAM_H
#define QUIC_STREAM_STREAM_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 3.1: sending part of a stream. */
typedef enum {
    QUIC_SEND_READY = 0,
    QUIC_SEND_SEND,
    QUIC_SEND_DATA_SENT,
    QUIC_SEND_DATA_RECVD,
    QUIC_SEND_RESET_SENT,
    QUIC_SEND_RESET_RECVD
} quic_send_state;

/* RFC 9000 3.2: receiving part of a stream. */
typedef enum {
    QUIC_RECV_RECV = 0,
    QUIC_RECV_SIZE_KNOWN,
    QUIC_RECV_DATA_RECVD,
    QUIC_RECV_DATA_READ,
    QUIC_RECV_RESET_RECVD,
    QUIC_RECV_RESET_READ
} quic_recv_state;

/* Events that drive the sending state machine. */
typedef enum {
    QUIC_SEND_EV_STREAM,      /* app queued the first STREAM/BLOCKED bytes */
    QUIC_SEND_EV_FIN_SENT,    /* all data incl. FIN has been sent */
    QUIC_SEND_EV_ACKED,       /* all data incl. FIN acknowledged */
    QUIC_SEND_EV_RESET,       /* app/endpoint sent RESET_STREAM */
    QUIC_SEND_EV_RESET_ACKED  /* RESET_STREAM acknowledged */
} quic_send_event;

/* Events that drive the receiving state machine. */
typedef enum {
    QUIC_RECV_EV_FIN,         /* STREAM with FIN: final size is known */
    QUIC_RECV_EV_ALL_DATA,    /* all stream data received */
    QUIC_RECV_EV_READ,        /* app read all buffered data */
    QUIC_RECV_EV_RESET        /* RESET_STREAM received */
} quic_recv_event;

/* Apply ev to *s. Returns 1 if the transition is allowed (and *s is
 * updated), 0 if ev is not valid in the current state (s unchanged). */
int quic_send_step(quic_send_state *s, quic_send_event ev);
int quic_recv_step(quic_recv_state *s, quic_recv_event ev);

#endif
