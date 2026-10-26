#ifndef SENTMETA_RECORD_H
#define SENTMETA_RECORD_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 A.1: real sent-packet metadata. Fixed-length ring, no dynamic
 * allocation. Tracks per-PN time_sent / ack_eliciting / in_flight / sent_bytes
 * and a running total of in-flight bytes (RFC 9002 7.4 bytes_in_flight). */

#define SENTMETA_CAP 256

/** One tracked sent packet (RFC 9002 A.1.1). */
typedef struct {
  u64 pn;            /**< packet number */
  u64 time_sent;     /**< send time, in the caller's clock unit */
  usz sent_bytes;    /**< packet size */
  int ack_eliciting; /**< 1 if it carried an ack-eliciting frame */
  int in_flight;     /**< 1 if its bytes count in total_in_flight */
  int used;          /**< 1 while the slot holds a packet */
} sentmeta_pkt;

/** The sent-packet ring and its running bytes-in-flight total. */
typedef struct {
  sentmeta_pkt pkts[SENTMETA_CAP]; /**< the ring; used marks a live slot */
  usz          count;              /**< live slots */
  usz          total_in_flight;    /**< bytes of in-flight live slots */
} sentmeta;

void sentmeta_init(sentmeta* m);

/** A packet to record as sent. */
typedef struct {
  u64 pn;            /**< packet number */
  u64 time_sent;     /**< send time */
  int ack_eliciting; /**< 1 if it carries an ack-eliciting frame */
  int in_flight;     /**< 1 if its bytes count in total_in_flight */
  usz sent_bytes;    /**< packet size */
} sentmeta_out;

/* RFC 9002 A.1 OnPacketSent: record one sent packet. Adds sent_bytes to
 * total_in_flight when the packet is in_flight. Returns 1, or 0 if full. */
int sentmeta_on_sent(sentmeta* m, const sentmeta_out* pkt);

/* Reclaim slot i: drop its bytes from total_in_flight and free the slot.
 * Shared by ACK (acked) and loss detection (lost) so the in-flight
 * accounting lives in one place (RFC 9002 7.4). */
void sentmeta_reclaim(sentmeta* m, usz i);

/* Keep pn tracked but stop counting its bytes in total_in_flight -- its
 * owner accounts for them some other way. No-op if pn is not tracked. */
void sentmeta_uncount(sentmeta* m, u64 pn);

/* Index of the slot holding pn, or SENTMETA_CAP if not tracked. */
usz sentmeta_find(const sentmeta* m, u64 pn);

#endif
