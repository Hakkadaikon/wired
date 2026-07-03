#include "tls/ext/tpverify/odcid.h"

#include "tls/ext/tpverify/ctcid.h"

/* RFC 9000 7.3 */
int quic_tpverify_odcid(quic_span sent_dcid, quic_span tp_odcid) {
  return quic_tpverify_cid_eq(sent_dcid, tp_odcid);
}
