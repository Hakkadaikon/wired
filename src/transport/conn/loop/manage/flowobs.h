#ifndef QUIC_MANAGE_FLOWOBS_H
#define QUIC_MANAGE_FLOWOBS_H

#include "common/platform/sys/syscall.h"

/* RFC 9312 3.3/3.4: heuristics an on-path observer uses to bound a flow.
 * A flow start is observable as the first Initial packet (long header,
 * non-zero version, Initial type). A Version Negotiation packet (long
 * header, version 0) is not a flow start. Flow end is not deterministic
 * from a single packet (it needs idle timing or a stateless reset match),
 * so only the start-side and version-negotiation signals are pure here. */

/* True if byte0 carries a long header with version 0: a Version Negotiation
 * packet (RFC 9000 17.2.1), which is not a flow start. */
int quic_manage_is_vneg(u8 byte0, u32 version);

/* True if this packet is observable as a flow start: a client Initial
 * (long header, non-zero version, Initial type). RFC 9312 3.3. */
int quic_manage_is_flow_start(u8 byte0, u32 version);

#endif
