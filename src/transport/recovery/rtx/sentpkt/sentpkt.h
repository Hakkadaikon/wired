#ifndef QUIC_SENTPKT_SENTPKT_H
#define QUIC_SENTPKT_SENTPKT_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 A.1: sent-packet tracking. Fixed-capacity ring buffer, no
 * dynamic allocation. Each slot records one in-flight packet. */

#define QUIC_SENTPKT_CAP 256

enum { QUIC_SP_INFLIGHT = 0, QUIC_SP_ACKED, QUIC_SP_LOST };

typedef struct {
  u64 pn;
  u64 time_sent;
  u64 size;
  u8  ack_eliciting;
  u8  state;
  u8  used;
} quic_sentpkt_entry;

typedef struct {
  quic_sentpkt_entry e[QUIC_SENTPKT_CAP];
} quic_sentpkt;

void quic_sentpkt_init(quic_sentpkt *t);

/* A packet to record as sent. */
typedef struct {
  u64 pn;
  u64 time;
  int ack_eliciting;
  usz size;
} quic_sentpkt_out;

/* Record an in-flight packet. Returns 1 on success, 0 if the table is full. */
int quic_sentpkt_on_send(quic_sentpkt *t, const quic_sentpkt_out *pkt);

/* Number of in-use slots (recorded, not yet reclaimed). */
usz quic_sentpkt_count(const quic_sentpkt *t);

/* An output slice for accumulated u64s (e.g. newly-acked packet numbers):
 * out[0..*n) is filled in, *n starts at the caller's count and is advanced. */
typedef struct {
  u64 *out;
  usz *n;
} quic_u64out;

#endif
