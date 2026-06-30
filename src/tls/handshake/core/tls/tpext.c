#include "tls/handshake/core/tls/tpext.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* RFC 9001 8.2: extension_type(2) + extension_data length(2) + data. */
usz quic_tpext_encode(u8 *buf, usz cap, const u8 *tp_data, usz tp_len)
{
    usz off = 4;
    if (tp_len > 0xFFFF || off + tp_len > cap) return 0;
    quic_put_be16(buf, QUIC_TPEXT_TYPE);
    quic_put_be16(buf + 2, (u16)tp_len);
    quic_put_bytes(buf, cap, &off, tp_data, tp_len); /* room checked above */
    return off;
}

/* Validate the 4-byte header and read the data length into *len. */
static int tpext_head(const u8 *buf, usz n, usz *len)
{
    if (n < 4 || ((u16)buf[0] << 8 | buf[1]) != QUIC_TPEXT_TYPE) return 0;
    *len = (usz)buf[2] << 8 | buf[3];
    return 4 + *len <= n;
}

usz quic_tpext_decode(const u8 *buf, usz n, const u8 **tp_data, usz *tp_len)
{
    usz len;
    if (!tpext_head(buf, n, &len)) return 0;
    *tp_data = buf + 4;
    *tp_len = len;
    return 4 + len;
}
