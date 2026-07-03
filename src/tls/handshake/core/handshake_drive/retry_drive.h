#ifndef QUIC_HANDSHAKE_DRIVE_RETRY_DRIVE_H
#define QUIC_HANDSHAKE_DRIVE_RETRY_DRIVE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 17.2.5: client reception of a Retry packet. Verify the Retry
 * Integrity Tag (RFC 9001 5.8) against the original DCID, extract the token,
 * and adopt the Retry's SCID as the new DCID for the next Initial. */

/* Destination for quic_retry_process: the extracted token (via the obuf) and
 * the Retry's SCID (the new DCID), new_dcid capped at QUIC_MAX_CID_LEN by
 * the caller. */
typedef struct {
  quic_obuf *token;
  u8        *new_dcid;
  u8        *new_dcil;
} quic_retry_process_out;

/* Verify and process a received Retry packet. On a valid tag returns 1 and
 * writes the token and new DCID into out. Returns 0 on a malformed packet or
 * bad tag, leaving outputs untouched. */
int quic_retry_process(
    quic_span retry_pkt, quic_span orig_dcid, const quic_retry_process_out *out);

/* RFC 9000 17.2.5: a client accepts at most one Retry. state is non-zero once
 * a Retry has been accepted; returns 1 to mean a further Retry must be
 * ignored. */
int quic_retry_already(int state);

#endif
