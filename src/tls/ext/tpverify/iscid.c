#include "tls/ext/tpverify/iscid.h"

#include "tls/ext/tpverify/ctcid.h"

/* RFC 9000 7.3 */
int quic_tpverify_iscid(
    const u8 *first_scid, u8 scid_len, const u8 *tp_iscid, u8 tp_len) {
  return quic_tpverify_cid_eq(first_scid, scid_len, tp_iscid, tp_len);
}
