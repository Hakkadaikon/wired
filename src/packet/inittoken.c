#include "packet/inittoken.h"
#include "varint/varint.h"
#include "util/bytes.h"

/* RFC 9000 17.2.2: Token Length(varint) + Token. */
usz quic_inittoken_put(u8 *buf, usz cap, const u8 *token, usz len)
{
    usz off = 0;
    if (!quic_varint_put(buf, cap, &off, len)) return 0;
    if (!quic_put_bytes(buf, cap, &off, token, len)) return 0;
    return off;
}

/* Read the Token Length varint and bound-check it against the remainder. */
static int take_tlen(const u8 *buf, usz n, usz *off, u64 *tlen)
{
    if (!quic_varint_take(buf, n, off, tlen)) return 0;
    return *tlen <= n - *off;
}

usz quic_inittoken_get(const u8 *buf, usz n, const u8 **token, usz *len)
{
    usz off = 0;
    u64 tlen;
    if (!take_tlen(buf, n, &off, &tlen)) return 0;
    *token = tlen ? buf + off : (const u8 *)0;
    *len = (usz)tlen;
    return off + (usz)tlen;
}
