#ifndef QUIC_TPVERIFY_ISCID_H
#define QUIC_TPVERIFY_ISCID_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 7.3: each endpoint checks initial_source_connection_id in the
 * peer's transport parameters equals the Source CID of the first packet it
 * received from that peer. Constant-time compare. 1 if matched, 0 on
 * TRANSPORT_PARAMETER_ERROR. */
int quic_tpverify_iscid(quic_span first_scid, quic_span tp_iscid);

#endif
