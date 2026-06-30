#ifndef QUIC_MANAGE_ZERORTT_POLICY_H
#define QUIC_MANAGE_ZERORTT_POLICY_H

/* RFC 9308 5.3: 0-RTT data can be replayed by an attacker, so only requests
 * that are idempotent or otherwise protected against replay may be sent in
 * 0-RTT. */

/* True if a request is safe to send as 0-RTT: it is idempotent, or the
 * application has its own replay protection. */
int quic_zerortt_safe(int is_idempotent, int replay_protected);

#endif
