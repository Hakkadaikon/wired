#include "tls/handshake/roles/sflight/certmsg.h"
#include "tls/handshake/core/tls/handshake.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* RFC 8446 4.4.2 CertificateEntry: cert_data<3> + extensions<2>=empty. */
#define QUIC_HS_CERTIFICATE 11

/* Write a 24-bit big-endian length at p. */
static void put_be24(u8 *p, u32 v)
{
    p[0] = (u8)(v >> 16); p[1] = (u8)(v >> 8); p[2] = (u8)v;
}

/* Header(4) + ctx_len(1) + list_len(3) + entry_len(3) + cert + ext_len(2). */
static int cert_fits(usz cert_len, usz cap)
{
    return cert_len <= 0xFFFFFF && 4 + 1 + 3 + 3 + cert_len + 2 <= cap;
}

/* One CertificateEntry into out at off; returns the offset past it. */
static usz put_entry(u8 *out, usz cap, usz off, const u8 *cert, usz cert_len)
{
    put_be24(out + off, (u32)cert_len);
    off += 3;
    quic_put_bytes(out, cap, &off, cert, cert_len); /* room checked above */
    quic_put_be16(out + off, 0);                    /* empty extensions */
    return off + 2;
}

int quic_sflight_certificate(const u8 *cert_der, usz cert_len,
                             u8 *out, usz cap, usz *out_len)
{
    usz off, end;
    if (!cert_fits(cert_len, cap)) return 0;
    off = quic_hs_begin(out, cap, QUIC_HS_CERTIFICATE);
    out[off] = 0;                                /* request_context length 0 */
    put_be24(out + off + 1, (u32)(cert_len + 5)); /* certificate_list length */
    end = put_entry(out, cap, off + 4, cert_der, cert_len);
    *out_len = end;
    quic_hs_finish(out, end);
    return 1;
}
