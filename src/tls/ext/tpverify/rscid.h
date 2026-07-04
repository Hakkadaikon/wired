#ifndef QUIC_TPVERIFY_RSCID_H
#define QUIC_TPVERIFY_RSCID_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

typedef struct {
  int       retry_occurred;
  quic_span retry_scid;
  quic_span tp_rscid;
  int       tp_present;
} quic_tpverify_rscid_in;

/* RFC 9000 7.3: retry_source_connection_id must be present iff a Retry was
 * processed, and then equal the Source CID of the Retry packet. A present-but-
 * unexpected, missing-but-expected, or mismatching value is a violation.
 * retry_occurred / tp_present are 0/1 flags. 1 if consistent, 0 on
 * TRANSPORT_PARAMETER_ERROR. */
int quic_tpverify_rscid(const quic_tpverify_rscid_in* in);

#endif
