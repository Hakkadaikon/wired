#include "tls/ext_versions.h"
#include "util/be.h"

/* RFC 8446 4.2.1: type(2) + ext_data length(2) + list length(1) + versions. */
usz quic_tls_ext_supported_versions(u8 *buf, usz cap)
{
    if (cap < 7) return 0;
    quic_put_be16(buf, QUIC_EXT_SUPPORTED_VERSIONS);
    quic_put_be16(buf + 2, 3);
    buf[4] = 2;
    quic_put_be16(buf + 5, QUIC_TLS13_VERSION);
    return 7;
}

/* The 4-byte header names supported_versions and its body fits in n. */
static int versions_header_ok(const u8 *buf, usz n)
{
    usz dlen = (usz)buf[2] << 8 | buf[3];
    return ((u16)buf[0] << 8 | buf[1]) == QUIC_EXT_SUPPORTED_VERSIONS && 4 + dlen <= n;
}

/* extension_type matches and the body is fully readable. */
static int versions_framed(const u8 *buf, usz n)
{
    if (n < 5) return 0;
    return versions_header_ok(buf, n) && ((usz)buf[2] << 8 | buf[3]) == (usz)buf[4] + 1;
}

/* list length is the declared even count of 2-byte versions. */
static usz versions_count(const u8 *buf)
{
    usz llen = buf[4];
    return (llen & 1) ? 0 : llen / 2;
}

/* The 2-byte version at index i in the list equals TLS 1.3. */
static int is_tls13_at(const u8 *buf, usz i)
{
    return ((u16)buf[5 + 2 * i] << 8 | buf[6 + 2 * i]) == QUIC_TLS13_VERSION;
}

/* Scan cnt versions for TLS 1.3. */
static int versions_scan(const u8 *buf, usz cnt)
{
    for (usz i = 0; i < cnt; i++)
        if (is_tls13_at(buf, i)) return 1;
    return 0;
}

int quic_tls_ext_versions_has_tls13(const u8 *buf, usz n)
{
    if (!versions_framed(buf, n)) return 0;
    return versions_scan(buf, versions_count(buf));
}
