#include "retrydrive/reconnect.h"
#include "util/bytes.h"

/* RFC 9000 17.2.5: token and SCID must fit the reconnection-state buffers. */
static int fits(usz token_len, usz scid_len)
{
    return token_len <= sizeof(((quic_retrydrive_state *)0)->token)
        && scid_len <= QUIC_MAX_CID_LEN;
}

/* RFC 9000 17.2.5.2 */
int quic_retrydrive_apply(const u8 *retry_token, usz token_len,
                          const u8 *retry_scid, usz scid_len,
                          quic_retrydrive_state *out)
{
    usz off = 0;
    if (!fits(token_len, scid_len)) return 0;
    quic_put_bytes(out->token, sizeof out->token, &off, retry_token, token_len);
    out->token_len = token_len;
    off = 0;
    quic_put_bytes(out->dcid, sizeof out->dcid, &off, retry_scid, scid_len);
    out->dcid_len = (u8)scid_len;
    out->received = 1;
    out->key_rederive = 1;
    return 1;
}
