#ifndef QUIC_SENTMETA_RECORD_H
#define QUIC_SENTMETA_RECORD_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 A.1: real sent-packet metadata. Fixed-length ring, no dynamic
 * allocation. Tracks per-PN time_sent / ack_eliciting / in_flight / sent_bytes
 * and a running total of in-flight bytes (RFC 9002 7.4 bytes_in_flight). */

#define QUIC_SENTMETA_CAP 256

typedef struct {
  u64 pn;
  u64 time_sent;
  usz sent_bytes;
  int ack_eliciting;
  int in_flight;
  int used;
} quic_sentmeta_pkt;

typedef struct {
  quic_sentmeta_pkt pkts[QUIC_SENTMETA_CAP];
  usz               count;
  usz               total_in_flight;
} quic_sentmeta;

void quic_sentmeta_init(quic_sentmeta* m);

/* A packet to record as sent. */
typedef struct {
  u64 pn;
  u64 time_sent;
  int ack_eliciting;
  int in_flight;
  usz sent_bytes;
} quic_sentmeta_out;

/* RFC 9002 A.1 OnPacketSent: record one sent packet. Adds sent_bytes to
 * total_in_flight when the packet is in_flight. Returns 1, or 0 if full. */
int quic_sentmeta_on_sent(quic_sentmeta* m, const quic_sentmeta_out* pkt);

/* Reclaim slot i: drop its bytes from total_in_flight and free the slot.
 * Shared by ACK (acked) and loss detection (lost) so the in-flight
 * accounting lives in one place (RFC 9002 7.4). */
void quic_sentmeta_reclaim(quic_sentmeta* m, usz i);

/* Index of the slot holding pn, or QUIC_SENTMETA_CAP if not tracked. */
usz quic_sentmeta_find(const quic_sentmeta* m, u64 pn);

#endif
