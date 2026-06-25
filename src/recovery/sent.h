#ifndef QUIC_RECOVERY_SENT_H
#define QUIC_RECOVERY_SENT_H

#include "sys/syscall.h"

/* RFC 9002 A: sent-packet tracking, ACK handling, and packet-threshold
 * loss detection. Fixed-capacity, no dynamic allocation. */

#define QUIC_SENT_CAP 256
#define QUIC_PACKET_THRESHOLD 3 /* kPacketThreshold */

enum { QUIC_PKT_INFLIGHT = 0, QUIC_PKT_ACKED, QUIC_PKT_LOST };

typedef struct {
    u64 pn;
    u64 size;
    u64 time_sent;
    u8 state;
    u8 used;
} quic_sent_pkt;

typedef struct {
    quic_sent_pkt pkts[QUIC_SENT_CAP];
    u64 bytes_in_flight;
    u64 largest_acked;
    int have_acked;
} quic_sent;

void quic_sent_init(quic_sent *s);

/* Record an in-flight packet. Returns 1 on success, 0 if the table is full. */
int quic_sent_on_send(quic_sent *s, u64 pn, u64 size, u64 time_sent);

/* Acknowledge packet pn. Idempotent: re-acking does not double-count.
 * Updates largest_acked (monotonic). Returns 1 if newly acked. */
int quic_sent_on_ack(quic_sent *s, u64 pn);

/* Mark in-flight packets at least kPacketThreshold below largest_acked as
 * lost; returns how many newly transitioned to lost. */
usz quic_sent_detect_loss(quic_sent *s);

#endif
