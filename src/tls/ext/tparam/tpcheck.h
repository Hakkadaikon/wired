#ifndef TPARAM_TPCHECK_H
#define TPARAM_TPCHECK_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 7.3 / 18.2: the client's initial_source_connection_id must be
 * authenticated against the Source CID of the first Initial packet received
 * from it. The check returns 1 on success, 0 on a
 * TRANSPORT_PARAMETER_ERROR. */

/* Whether two connection IDs are byte-for-byte equal. */
int tparam_cid_match(wired_span got, wired_span expected);

/* initial_source_connection_id must equal the peer's observed Source CID. */
int tparam_check_initial_scid(wired_span got, wired_span observed);

/* RFC 9000 18.2: validate the value of a received integer-valued transport
 * parameter against its per-parameter range. Returns 1 if value is within
 * range (or id carries no range constraint), 0 if it is invalid -- the
 * caller closes with TRANSPORT_PARAMETER_ERROR:
 *   - max_udp_payload_size (0x03): values below 1200 are invalid.
 *   - ack_delay_exponent (0x0a): values above 20 are invalid.
 *   - max_ack_delay (0x0b): values of 2^14 or greater are invalid.
 *   - active_connection_id_limit (0x0e): must be at least 2. */
int tparam_range_ok(u64 id, u64 value);

/* RFC 9000 7.4 / 18.2: walk a client's whole transport-parameter sequence
 * tp and return 1 only if every TLV is well-framed, none is server-only
 * (original_destination_connection_id, stateless_reset_token,
 * preferred_address, retry_source_connection_id) and every
 * range-constrained parameter (tparam_range_ok) holds one in-range varint;
 * 0 is a TRANSPORT_PARAMETER_ERROR. */
int tparam_client_tp_ok(wired_span tp);

#endif
