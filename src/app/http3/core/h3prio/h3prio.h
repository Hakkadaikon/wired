#ifndef QUIC_H3PRIO_H3PRIO_H
#define QUIC_H3PRIO_H3PRIO_H

#include "common/platform/sys/syscall.h"

/* RFC 9218 10: server scheduling guidance for HTTP responses that share a
 * connection. "It is RECOMMENDED that ... servers respect the urgency
 * parameter ..., sending higher-urgency responses before lower-urgency
 * responses." "Non-incremental responses of the same urgency SHOULD be
 * served by prioritizing bandwidth allocation in ascending order of the
 * stream ID". This module computes ONLY the send order a round-robin pump
 * should visit its slots in; it does not send anything itself, mirroring
 * app/datagram/dgpriority's split of responsibility (compare/pick there,
 * order here since a round-robin pass needs a full visiting order, not a
 * single best pick). Incremental responses of the same urgency share
 * bandwidth by nature of the caller's round-robin pass visiting every slot
 * once per pass regardless of this order (RFC 9218 10: "share bandwidth
 * among them") -- ordering incrementals by stream ID as well just makes
 * that visiting order deterministic, it does not change how much of the
 * pass each one gets. */

/** One send candidate a round-robin pass is choosing an order over: a
 * slot's own priority (RFC 9218 4) plus the stream id RFC 9218 10's
 * tie-break sorts by. in_use marks whether the slot actually holds a
 * live response at all -- a caller iterating a fixed-size slot table
 * passes every slot, in_use false ones sort last so they are visited (and
 * skipped) only after every live one. */
// NOLINTNEXTLINE(clang-analyzer-optin.performance.Padding)
typedef struct {
  u8  urgency;     /**< RFC 9218 4.1, 0..7, lower is higher precedence */
  u8  incremental; /**< RFC 9218 4.2 */
  u64 stream_id;   /**< RFC 9218 10's same-urgency tie-break key */
  int in_use;      /**< 0: not a live candidate, sorts after every live one */
} h3prio_candidate;

/** Fill order[0..n) with a permutation of 0..n-1 that visits `c` in RFC
 * 9218 10 priority order: ascending urgency first (lower urgency = higher
 * precedence, RFC 9218 4.1), then ascending stream_id among equal
 * urgencies (RFC 9218 10's non-incremental tie-break, applied uniformly
 * since it also gives incrementals of equal urgency a deterministic,
 * stable visiting order without changing their round-robin bandwidth
 * share). Every !in_use candidate sorts after every in_use one, in their
 * own index order among themselves.
 * @param c candidates, c[0..n)
 * @param n candidate/order count
 * @param order receives the visiting order, order[0..n) */
void h3prio_order(const h3prio_candidate* c, usz n, usz* order);

#endif
