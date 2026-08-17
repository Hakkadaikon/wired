#ifndef QUIC_DGPRIORITY_DGPRIORITY_H
#define QUIC_DGPRIORITY_DGPRIORITY_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9221 5.1: "QUIC implementations SHOULD present an API to applications
 * to assign relative priorities to DATAGRAM frames with respect to each
 * other and to QUIC streams." DATAGRAM frames carry no priority of their
 * own on the wire (RFC 9221 defines none), so this is purely an
 * application-facing scheduling aid: the application assigns each DATAGRAM
 * flow (and each stream, via its own urgency -- e.g. quic_h3_priority's
 * RFC 9218 4 urgency byte when HTTP/3 is in use) a comparable urgency
 * value, and this module orders send candidates by it. The scale (0..7,
 * lower is more urgent, default 3) matches RFC 9218 4's HTTP/3 urgency so
 * the two compare directly, but this module has no dependency on the h3
 * domain -- it operates on raw urgency bytes, keeping DATAGRAM
 * (transport-level, RFC 9221) independent of HTTP/3 (application-level,
 * RFC 9218). */

#define QUIC_DGPRIORITY_DEFAULT 3
#define QUIC_DGPRIORITY_MAX 7

/* True if u is a valid urgency value (0..7). */
int quic_dgpriority_valid(u8 u);

/* True if urgency a outranks urgency b (lower value = higher priority,
 * matching quic_h3_priority_higher's convention so a DATAGRAM's urgency and
 * a stream's urgency compare with the same rule). Equal urgencies are not
 * "higher" either way -- the caller picks its own tie-break (e.g. FIFO). */
int quic_dgpriority_higher(u8 urg_a, u8 urg_b);

/** One DATAGRAM send candidate: the payload to send and its urgency. */
typedef struct {
  wired_span data;
  u8         urgency;
} quic_dgpriority_candidate;

/* Scan candidates[0..n) and return the index of the one with the highest
 * priority (lowest urgency); ties keep the earliest (lowest index), so
 * calling this repeatedly over a stable list drains it in a deterministic,
 * priority-then-arrival order. Returns -1 if n == 0. */
i64 quic_dgpriority_pick(const quic_dgpriority_candidate* candidates, usz n);

#endif
