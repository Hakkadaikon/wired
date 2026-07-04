#ifndef QUIC_HSPTO_HSPTO_H
#define QUIC_HSPTO_HSPTO_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 6.2.2.1: handshake-space PTO. Before the handshake is confirmed
 * max_ack_delay is excluded from the PTO. Times in us. Extends pto.c. */

#define QUIC_HSPTO_GRANULARITY 1000 /* kGranularity = 1ms */

/* RTT inputs to the PTO computation. */
typedef struct {
  u64 srtt;
  u64 rttvar;
} quic_hspto_rtt;

/* Remaining inputs: backoff, granularity, and the handshake-confirmed ack
 * delay term. */
typedef struct {
  u32 pto_count;
  u64 granularity;
  int handshake_confirmed;
  u64 max_ack_delay;
} quic_hspto_ctx;

/* PTO = srtt + max(4*rttvar, granularity) [+ max_ack_delay if confirmed],
 * scaled by 2^pto_count (clamped). */
u64 quic_hspto_duration(quic_hspto_rtt rtt, const quic_hspto_ctx* ctx);

#endif
