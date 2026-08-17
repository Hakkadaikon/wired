#include "tls/ext/tpverify/iscid.h"

#include "tls/ext/tpverify/ctcid.h"

/* RFC 9000 7.3 */
int tpverify_iscid(wired_span first_scid, wired_span tp_iscid) {
  return tpverify_cid_eq(first_scid, tp_iscid);
}
