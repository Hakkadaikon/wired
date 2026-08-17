#ifndef QUIC_PENDING1RTT_PENDING1RTT_H
#define QUIC_PENDING1RTT_PENDING1RTT_H

#include "common/platform/sys/syscall.h"

/**
 * @file
 * RFC 9001 5.7: while the TLS handshake is not complete, an endpoint must
 * not process an incoming 1-RTT protected packet (it does not yet have a
 * confirmed peer identity); it may instead store the packet for later
 * decryption once the handshake completes. This is a small fixed-capacity
 * FIFO of raw datagram bytes for exactly that purpose -- storage only, no
 * decryption, no parsing.
 */

/** One stored datagram's capacity, sized to a common Ethernet MTU. */
#define QUIC_PENDING1RTT_MAX_LEN 1500

/** Maximum number of packets held at once. Bounded: RFC 9001 5.7 buffering
 * is a courtesy for reordered packets around the handshake boundary, not an
 * unbounded queue an attacker could use to exhaust memory. */
#define QUIC_PENDING1RTT_CAP 4

/** Fixed-capacity FIFO of stored raw datagrams awaiting handshake
 * completion. */
typedef struct {
  u8  buf[QUIC_PENDING1RTT_CAP][QUIC_PENDING1RTT_MAX_LEN];
  usz len[QUIC_PENDING1RTT_CAP];
  usz count; /* number of slots in use, filled from index 0 */
} pending1rtt;

/** Start empty. */
void pending1rtt_init(pending1rtt* q);

/** RFC 9001 5.7: 1 if incoming 1-RTT packets must not be processed yet
 * (the handshake is not complete). */
int pending1rtt_should_defer(int handshake_complete);

/** Store one datagram's bytes. Returns 1 on success, 0 if it exceeds
 * QUIC_PENDING1RTT_MAX_LEN or the queue is already at QUIC_PENDING1RTT_CAP
 * (both fail closed: the caller drops the packet rather than blocking). */
int pending1rtt_store(pending1rtt* q, const u8* data, usz len);

/** Number of packets currently stored. */
usz pending1rtt_count(const pending1rtt* q);

/** Take the packet at FIFO position i (0 = oldest) without removing it;
 * *data points into q, *len is its length. Returns 1 if i < count. */
int pending1rtt_peek(const pending1rtt* q, usz i, const u8** data, usz* len);

/** Empty the queue (call once the handshake completes and every stored
 * packet has been re-fed through the normal receive path). */
void pending1rtt_clear(pending1rtt* q);

#endif
