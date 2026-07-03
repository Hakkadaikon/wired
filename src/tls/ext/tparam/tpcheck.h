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
int quic_tparam_cid_match(quic_span got, quic_span expected);

/* initial_source_connection_id must equal the peer's observed Source CID. */
int quic_tparam_check_initial_scid(quic_span got, quic_span observed);

/* original_destination_connection_id must equal the DCID the client sent. */
int quic_tparam_check_original_dcid(quic_span got, quic_span sent_dcid);

typedef struct {
  int       did_retry;
  int       has_param;
  quic_span got;
  quic_span retry_scid;
} quic_tparam_retry_scid_in;

/* retry_source_connection_id must be present and match the Retry Source CID
 * exactly when a Retry was processed, and absent otherwise. did_retry and
 * has_param are 0/1 flags. */
int quic_tparam_check_retry_scid(const quic_tparam_retry_scid_in *in);

#endif
