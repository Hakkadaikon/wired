#include "test.h"
#include "tls/handshake/roles/sflight/certmsg.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/cert.h"

/* RFC 8446 4.4.2: the built Certificate message must parse back with an empty
 * request context and the same end-entity cert_data. */
void test_sflight_certmsg(void)
{
    const u8 der[7] = {0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
    u8 out[64];
    usz out_len, body_len;
    u8 type;
    const u8 *ctx;
    u32 ctx_len;
    quic_tls_cert_entry first;

    CHECK(quic_sflight_certificate(der, sizeof(der), out, sizeof(out),
                                   &out_len));
    CHECK(quic_hs_parse(out, out_len, &type, &body_len) == 4);
    CHECK(type == 11);
    CHECK(4 + body_len == out_len);

    CHECK(quic_tls_cert_parse(out + 4, body_len, &ctx, &ctx_len, &first));
    CHECK(ctx_len == 0);                       /* empty request context */
    CHECK(first.cert_len == sizeof(der));
    CHECK(first.cert_data[0] == 0x30 && first.cert_data[6] == 0x05);

    CHECK(!quic_sflight_certificate(der, sizeof(der), out, 4, &out_len));
}
