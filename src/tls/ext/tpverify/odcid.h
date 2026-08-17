#ifndef QUIC_TPVERIFY_ODCID_H
#define QUIC_TPVERIFY_ODCID_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 7.3: the client checks original_destination_connection_id in the
 * server's transport parameters equals the Destination CID it placed in its
 * first Initial. Constant-time compare. 1 if matched, 0 on
 * TRANSPORT_PARAMETER_ERROR. */
int tpverify_odcid(wired_span sent_dcid, wired_span tp_odcid);

#endif
