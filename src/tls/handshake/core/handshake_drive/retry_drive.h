#ifndef QUIC_HANDSHAKE_DRIVE_RETRY_DRIVE_H
#define QUIC_HANDSHAKE_DRIVE_RETRY_DRIVE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.2.5: client reception of a Retry packet. Verify the Retry
 * Integrity Tag (RFC 9001 5.8) against the original DCID, extract the token,
 * and adopt the Retry's SCID as the new DCID for the next Initial. */

/* Verify and process a received Retry packet. On a valid tag returns 1 and
 * writes the token (out_token / *token_len) and new DCID (new_dcid /
 * *new_dcil, the Retry's SCID). Returns 0 on a malformed packet or bad tag,
 * leaving outputs untouched. */
int quic_retry_process(const u8 *retry_pkt, usz len,
                       const u8 *orig_dcid, u8 odcil,
                       u8 *out_token, usz *token_len,
                       u8 *new_dcid, u8 *new_dcil);

/* RFC 9000 17.2.5: a client accepts at most one Retry. state is non-zero once
 * a Retry has been accepted; returns 1 to mean a further Retry must be
 * ignored. */
int quic_retry_already(int state);

#endif
