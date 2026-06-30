#include "tls/ext/tpverify/odcid.h"
#include "tls/ext/tpverify/ctcid.h"

/* RFC 9000 7.3 */
int quic_tpverify_odcid(const u8 *sent_dcid, u8 sent_len,
                        const u8 *tp_odcid, u8 tp_len)
{
    return quic_tpverify_cid_eq(sent_dcid, sent_len, tp_odcid, tp_len);
}
