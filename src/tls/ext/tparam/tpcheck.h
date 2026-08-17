#ifndef QUIC_TPARAM_TPCHECK_H
#define QUIC_TPARAM_TPCHECK_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 7.3 / 18.2: connection-ID transport parameters must be
 * authenticated against the connection IDs actually observed on the wire.
 *
 * - initial_source_connection_id: both endpoints check the value matches the
 *   Source CID of the first Initial packet received from the peer.
 * - original_destination_connection_id: the client checks the value matches
 *   the Destination CID it placed in its first Initial.
 * - retry_source_connection_id: present iff a Retry was processed; the client
 *   checks it matches the Source CID of the Retry packet. A mismatch, a
 *   missing-but-expected, or a present-but-unexpected value is an error.
 *
 * Each check returns 1 on success, 0 on a TRANSPORT_PARAMETER_ERROR. */

/* Whether two connection IDs are byte-for-byte equal. */
int tparam_cid_match(wired_span got, wired_span expected);

/* initial_source_connection_id must equal the peer's observed Source CID. */
int tparam_check_initial_scid(wired_span got, wired_span observed);

/* original_destination_connection_id must equal the DCID the client sent. */
int tparam_check_original_dcid(wired_span got, wired_span sent_dcid);

/** Inputs for the retry_source_connection_id presence/match check. */
typedef struct {
  int        did_retry;
  int        has_param;
  wired_span got;
  wired_span retry_scid;
} tparam_retry_scid_in;

/* retry_source_connection_id must be present and match the Retry Source CID
 * exactly when a Retry was processed, and absent otherwise. did_retry and
 * has_param are 0/1 flags. */
int tparam_check_retry_scid(const tparam_retry_scid_in* in);

/* RFC 9000 18.2: validate the value of a received integer-valued transport
 * parameter against its per-parameter range. Returns 1 if value is within
 * range (or id carries no range constraint), 0 if it is invalid -- the
 * caller closes with TRANSPORT_PARAMETER_ERROR:
 *   - max_udp_payload_size (0x03): values below 1200 are invalid.
 *   - ack_delay_exponent (0x0a): values above 20 are invalid.
 *   - max_ack_delay (0x0b): values of 2^14 or greater are invalid.
 *   - active_connection_id_limit (0x0e): must be at least 2. */
int tparam_range_ok(u64 id, u64 value);

#endif
