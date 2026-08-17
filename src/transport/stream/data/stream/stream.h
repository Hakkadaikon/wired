#ifndef STREAM_STREAM_H
#define STREAM_STREAM_H

#include "common/platform/sys/syscall.h"

/** RFC 9000 3.1: sending part of a stream. */
typedef enum {
  SEND_READY = 0,
  SEND_SEND,
  SEND_DATA_SENT,
  SEND_DATA_RECVD,
  SEND_RESET_SENT,
  SEND_RESET_RECVD
} send_state;

/** RFC 9000 3.2: receiving part of a stream. */
typedef enum {
  RECV_RECV = 0,
  RECV_SIZE_KNOWN,
  RECV_DATA_RECVD,
  RECV_DATA_READ,
  RECV_RESET_RECVD,
  RECV_RESET_READ
} recv_state;

/** Events that drive the sending state machine. */
typedef enum {
  SEND_EV_STREAM,     /* app queued the first STREAM/BLOCKED bytes */
  SEND_EV_FIN_SENT,   /* all data incl. FIN has been sent */
  SEND_EV_ACKED,      /* all data incl. FIN acknowledged */
  SEND_EV_RESET,      /* app/endpoint sent RESET_STREAM */
  SEND_EV_RESET_ACKED /* RESET_STREAM acknowledged */
} send_event;

/** Events that drive the receiving state machine. */
typedef enum {
  RECV_EV_FIN,      /* STREAM with FIN: final size is known */
  RECV_EV_ALL_DATA, /* all stream data received */
  RECV_EV_READ,     /* app read all buffered data */
  RECV_EV_RESET     /* RESET_STREAM received */
} recv_event;

/* Apply ev to *s. Returns 1 if the transition is allowed (and *s is
 * updated), 0 if ev is not valid in the current state (s unchanged). */
int send_step(send_state* s, send_event ev);
int recv_step(recv_state* s, recv_event ev);

#endif
