#ifndef QUIC_RTXBYTES_RTXSTORE_H
#define QUIC_RTXBYTES_RTXSTORE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9002 13.3: to retransmit the contents of a lost packet, the sender
 * keeps the actual frame bytes it sent, keyed by packet number, until the
 * packet is acknowledged or the bytes are reclaimed. Fixed-capacity ring
 * buffer, no dynamic allocation. */

#define QUIC_RTXBYTES_SLOTS 64
#define QUIC_RTXBYTES_FRAME 1200

typedef struct {
  u64 pn;
  u8  data[QUIC_RTXBYTES_FRAME];
  usz len;
  u8  used;
} quic_rtxbytes_slot;

typedef struct {
  quic_rtxbytes_slot s[QUIC_RTXBYTES_SLOTS];
  usz                next;
} quic_rtxbytes;

void quic_rtxbytes_init(quic_rtxbytes *st);

/* Keep the frame bytes sent in packet pn. Returns 1 on success, 0 if the
 * frame is too large. The oldest slot is overwritten when the ring wraps. */
int quic_rtxbytes_store(quic_rtxbytes *st, u64 pn, quic_span frame);

/* Look up the frame bytes kept for packet pn. On hit, *out is a view into the
 * store; returns 1. Returns 0 if pn is not held. */
int quic_rtxbytes_get(const quic_rtxbytes *st, u64 pn, quic_span *out);

#endif
