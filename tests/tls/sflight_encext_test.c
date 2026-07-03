#include "test.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/tpext.h"
#include "tls/handshake/roles/sflight/encext.h"

/* RFC 8446 4.3.1 / RFC 9001 8.2: EncryptedExtensions wraps the transport
 * parameters extension; the header, the extensions block, and the 0x39
 * extension must all be readable back. */
void test_sflight_encext(void) {
  const u8  tp[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  u8        out[64];
  usz       out_len, body_len, used;
  u8        type;
  const u8 *body;
  quic_span tpd;

  CHECK(quic_sflight_encrypted_extensions(
      tp, sizeof(tp), out, sizeof(out), &out_len));
  /* handshake header: type 0x08 and a length that matches out_len. */
  CHECK(quic_hs_parse(quic_span_of(out, out_len), &type, &body_len) == 4);
  CHECK(type == QUIC_HS_ENCRYPTED_EXT);
  CHECK(4 + body_len == out_len);

  /* body: 2-byte extensions length then the 0x39 extension. */
  body = out + 4;
  CHECK(((usz)body[0] << 8 | body[1]) == body_len - 2);
  used = quic_tpext_decode(quic_span_of(body + 2, body_len - 2), &tpd);
  CHECK(used == body_len - 2);
  CHECK(tpd.n == sizeof(tp));
  CHECK(tpd.p[0] == 0xaa && tpd.p[4] == 0xee);

  /* a tight cap (one byte short) must be refused. */
  CHECK(!quic_sflight_encrypted_extensions(
      tp, sizeof(tp), out, out_len - 1, &out_len));
}
