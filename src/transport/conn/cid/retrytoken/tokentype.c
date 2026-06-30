#include "transport/conn/cid/retrytoken/tokentype.h"
#include "common/bytes/util/bytes.h"

/* RFC 9000 8.1.1/8.1.3: prefix the body with one type-tag byte. */
static usz tag(u8 *out, usz cap, u8 t, const u8 *body, usz body_len)
{
    usz off = 1;
    if (cap < 1) return 0;
    out[0] = t;
    if (!quic_put_bytes(out, cap, &off, body, body_len)) return 0;
    return off;
}

usz quic_token_tag_retry(u8 *out, usz cap, const u8 *body, usz body_len)
{
    return tag(out, cap, QUIC_TOKEN_TAG_RETRY, body, body_len);
}

usz quic_token_tag_newtoken(u8 *out, usz cap, const u8 *body, usz body_len)
{
    return tag(out, cap, QUIC_TOKEN_TAG_NEWTOKEN, body, body_len);
}

int quic_token_is_retry(const u8 *token, usz len)
{
    return len > 0 && token[0] == QUIC_TOKEN_TAG_RETRY;
}
