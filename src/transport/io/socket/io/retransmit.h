#ifndef QUIC_IO_RETRANSMIT_H
#define QUIC_IO_RETRANSMIT_H

#include "common/platform/sys/syscall.h"

/* A fixed-capacity FIFO of frame payloads awaiting retransmission. When a
 * packet is declared lost (RFC 9002 6), its frames are queued here and later
 * resent in a new packet with a strictly greater packet number. */

#define QUIC_RTX_SLOTS 64
#define QUIC_RTX_FRAME 1200

typedef struct {
    u8 data[QUIC_RTX_FRAME];
    usz len;
} quic_rtx_frame;

typedef struct {
    quic_rtx_frame slots[QUIC_RTX_SLOTS];
    usz head; /* next slot to pop */
    usz tail; /* next slot to push */
    usz count;
} quic_rtx_queue;

void quic_rtx_init(quic_rtx_queue *q);

/* Queue a lost frame for retransmission. Returns 1 on success, 0 if the
 * queue is full or the frame is too large. */
int quic_rtx_push(quic_rtx_queue *q, const u8 *frame, usz len);

/* Pop the oldest queued frame into out (capacity cap). Returns its length,
 * or 0 if the queue is empty or out is too small. */
usz quic_rtx_pop(quic_rtx_queue *q, u8 *out, usz cap);

#endif
