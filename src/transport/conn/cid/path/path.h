#ifndef QUIC_PATH_PATH_H
#define QUIC_PATH_PATH_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 8.2/9: path validation and connection migration. A path is
 * validated only by a PATH_RESPONSE matching the PATH_CHALLENGE we sent on
 * it; before validation a path is anti-amplification limited (send at most
 * 3x received); migration to a path is confirmed only after validation, and
 * at most one path is the confirmed active target. */

#define QUIC_PATH_COUNT 2

typedef struct {
  u64 challenge;         /* outstanding PATH_CHALLENGE payload; 0 = none sent */
  u64 challenge_sent_at; /* clock reading when challenge was sent */
  u64 bytes_sent;
  u64 bytes_received;
  u8  validated;
  u8  confirmed;
} quic_path_state;

typedef struct {
  quic_path_state paths[QUIC_PATH_COUNT];
  usz             active; /* index of the active path */
} quic_path;

void quic_path_init(quic_path* p);

/* Record a PATH_CHALLENGE of payload `value` (must be nonzero) sent on path
 * at clock reading `now` -- `now` seeds the RFC 9000 8.2.4 abandon timer. */
void quic_path_send_challenge(quic_path* p, usz path, u64 value, u64 now);

/* Receive a PATH_RESPONSE on path; validates it only if value matches the
 * outstanding challenge. Returns 1 if newly validated. */
int quic_path_recv_response(quic_path* p, usz path, u64 value);

/* Whether `n` more bytes may be sent on path under anti-amplification. */
int quic_path_can_send(const quic_path* p, usz path, u64 n);

/* Confirm migration to path. Refused unless that path is validated; on
 * success it becomes the sole confirmed path and the active path. */
int quic_path_confirm(quic_path* p, usz path);

/* RFC 9000 8.2.4: whether path validation should be abandoned -- an
 * outstanding challenge (not yet validated) whose age (now -
 * challenge_sent_at) has reached three times pto. */
int quic_path_abandon_due(const quic_path* p, usz path, u64 now, u64 pto);

/* RFC 9000 9.3.2: on path validation failure, revert to the last validated
 * (confirmed) peer address -- clears path's outstanding challenge and
 * leaves p->active/confirmed untouched (still pointing at the prior
 * validated path, since confirm() is only ever granted to a validated
 * path). A no-op if path had no outstanding challenge. */
void quic_path_revert(quic_path* p, usz path);

#endif
