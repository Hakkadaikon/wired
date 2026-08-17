#ifndef SENTMETA_RECORD_H
#define SENTMETA_RECORD_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 A.1: real sent-packet metadata. Fixed-length ring, no dynamic
 * allocation. Tracks per-PN time_sent / ack_eliciting / in_flight / sent_bytes
 * and a running total of in-flight bytes (RFC 9002 7.4 bytes_in_flight). */

#define SENTMETA_CAP 256

typedef struct {
  u64 pn;
  u64 time_sent;
  usz sent_bytes;
  int ack_eliciting;
  int in_flight;
  int used;
} sentmeta_pkt;

typedef struct {
  sentmeta_pkt pkts[SENTMETA_CAP];
  usz          count;
  usz          total_in_flight;
} sentmeta;

void sentmeta_init(sentmeta* m);

/** A packet to record as sent. */
typedef struct {
  u64 pn;
  u64 time_sent;
  int ack_eliciting;
  int in_flight;
  usz sent_bytes;
} sentmeta_out;

/* RFC 9002 A.1 OnPacketSent: record one sent packet. Adds sent_bytes to
 * total_in_flight when the packet is in_flight. Returns 1, or 0 if full. */
int sentmeta_on_sent(sentmeta* m, const sentmeta_out* pkt);

/* Reclaim slot i: drop its bytes from total_in_flight and free the slot.
 * Shared by ACK (acked) and loss detection (lost) so the in-flight
 * accounting lives in one place (RFC 9002 7.4). */
void sentmeta_reclaim(sentmeta* m, usz i);

/* Index of the slot holding pn, or SENTMETA_CAP if not tracked. */
usz sentmeta_find(const sentmeta* m, u64 pn);

#endif
