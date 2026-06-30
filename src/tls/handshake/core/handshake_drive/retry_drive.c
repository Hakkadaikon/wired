#include "tls/handshake/core/handshake_drive/retry_drive.h"
#include "packet/retry.h"
#include "tls/handshake/core/tls/retry_tag.h"
#include "common/bytes/util/bytes.h"

/* Copy the parsed token and the Retry SCID (the next DCID) to the outputs. */
static void retry_emit(const quic_retry_packet *r, u8 *out_token,
                       usz *token_len, u8 *new_dcid, u8 *new_dcil)
{
    usz off = 0;
    quic_put_bytes(out_token, r->token_len, &off, r->token, r->token_len);
    *token_len = r->token_len;
    off = 0;
    quic_put_bytes(new_dcid, r->scid_len, &off, r->scid, r->scid_len);
    *new_dcil = r->scid_len;
}

int quic_retry_process(const u8 *retry_pkt, usz len,
                       const u8 *orig_dcid, u8 odcil,
                       u8 *out_token, usz *token_len,
                       u8 *new_dcid, u8 *new_dcil)
{
    quic_retry_packet r;
    if (quic_retry_parse(retry_pkt, len, &r) == 0) return 0;
    if (!quic_retry_verify(orig_dcid, odcil, retry_pkt, len)) return 0;
    retry_emit(&r, out_token, token_len, new_dcid, new_dcil);
    return 1;
}

int quic_retry_already(int state)
{
    return state != 0;
}
