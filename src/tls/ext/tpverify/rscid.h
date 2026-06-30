#ifndef QUIC_TPVERIFY_RSCID_H
#define QUIC_TPVERIFY_RSCID_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 7.3: retry_source_connection_id must be present iff a Retry was
 * processed, and then equal the Source CID of the Retry packet. A present-but-
 * unexpected, missing-but-expected, or mismatching value is a violation.
 * retry_occurred / tp_present are 0/1 flags. 1 if consistent, 0 on
 * TRANSPORT_PARAMETER_ERROR. */
int quic_tpverify_rscid(int retry_occurred,
                        const u8 *retry_scid, u8 retry_len,
                        const u8 *tp_rscid, u8 tp_len, int tp_present);

#endif
