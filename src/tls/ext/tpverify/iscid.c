#include "tls/ext/tpverify/iscid.h"

#include "tls/ext/tpverify/ctcid.h"

/* RFC 9000 7.3 */
int quic_tpverify_iscid(quic_span first_scid, quic_span tp_iscid) {
  return quic_tpverify_cid_eq(first_scid, tp_iscid);
}
