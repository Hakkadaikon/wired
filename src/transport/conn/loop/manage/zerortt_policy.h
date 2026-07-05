#ifndef QUIC_MANAGE_ZERORTT_POLICY_H
#define QUIC_MANAGE_ZERORTT_POLICY_H

/* RFC 9308 5.3: 0-RTT data can be replayed by an attacker, so only requests
 * that are idempotent or otherwise protected against replay may be sent in
 * 0-RTT. */

/* True if a request is safe to send as 0-RTT: it is idempotent, or the
 * application has its own replay protection. */
int quic_zerortt_safe(int is_idempotent, int replay_protected);

/* RFC 8446 8.1 / RFC 9001 9.2: accept 0-RTT data only when the application
 * policy allows it AND the presenting ticket is on its first use (a replayed
 * ticket is refused regardless of policy). */
int quic_zerortt_replay_ok(int policy_safe, int ticket_first_use);

#endif
