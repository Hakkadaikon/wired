#include "tls/ext/tpverify/rscid.h"

#include "tls/ext/tpverify/ctcid.h"

/* RFC 9000 7.3: presence of the parameter must agree with whether a Retry
 * was processed. */
static int presence_ok(int retry_occurred, int tp_present) {
  return (!retry_occurred) == (!tp_present);
}

/* RFC 9000 7.3 */
int quic_tpverify_rscid(const quic_tpverify_rscid_in* in) {
  if (!presence_ok(in->retry_occurred, in->tp_present)) return 0;
  if (!in->retry_occurred) return 1;
  return quic_tpverify_cid_eq(in->retry_scid, in->tp_rscid);
}
