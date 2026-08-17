#include "tls/ext/tpverify/odcid.h"

#include "tls/ext/tpverify/ctcid.h"

/* RFC 9000 7.3 */
int quic_tpverify_odcid(wired_span sent_dcid, wired_span tp_odcid) {
  return quic_tpverify_cid_eq(sent_dcid, tp_odcid);
}
