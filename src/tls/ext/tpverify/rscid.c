#include "tls/ext/tpverify/rscid.h"

#include "tls/ext/tpverify/ctcid.h"

/* RFC 9000 7.3: presence of the parameter must agree with whether a Retry
 * was processed. */
static int presence_ok(int retry_occurred, int tp_present) {
  return (!retry_occurred) == (!tp_present);
}

/* RFC 9000 7.3 */
int quic_tpverify_rscid(
    int       retry_occurred,
    const u8 *retry_scid,
    u8        retry_len,
    const u8 *tp_rscid,
    u8        tp_len,
    int       tp_present) {
  if (!presence_ok(retry_occurred, tp_present)) return 0;
  if (!retry_occurred) return 1;
  return quic_tpverify_cid_eq(retry_scid, retry_len, tp_rscid, tp_len);
}
