#include "test.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/roles/sflight/certmsg.h"

/* RFC 8446 4.4.2: the built Certificate message must parse back with an empty
 * request context and the same end-entity cert_data. */
void test_sflight_certmsg(void) {
  const u8            der[7] = {0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
  u8                  out[64];
  usz                 body_len;
  u8                  type;
  quic_span           ctx;
  quic_tls_cert_entry first;
  quic_obuf           ob = quic_obuf_of(out, sizeof(out));

  CHECK(quic_sflight_certificate(quic_span_of(der, sizeof(der)), &ob));
  CHECK(quic_hs_parse(quic_span_of(out, ob.len), &type, &body_len) == 4);
  CHECK(type == 11);
  CHECK(4 + body_len == ob.len);

  CHECK(quic_tls_cert_parse(quic_span_of(out + 4, body_len), &ctx, &first));
  CHECK(ctx.n == 0); /* empty request context */
  CHECK(first.cert_len == sizeof(der));
  CHECK(first.cert_data[0] == 0x30 && first.cert_data[6] == 0x05);

  ob = quic_obuf_of(out, 4);
  CHECK(!quic_sflight_certificate(quic_span_of(der, sizeof(der)), &ob));
}
