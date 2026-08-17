#include "test.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/tpext.h"
#include "tls/handshake/roles/sflight/encext.h"

/* RFC 8446 4.3.1 / RFC 9001 8.2: EncryptedExtensions wraps the transport
 * parameters extension; the header, the extensions block, and the 0x39
 * extension must all be readable back. */
void test_sflight_encext(void) {
  const u8   tp[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  u8         out[64];
  usz        body_len, used;
  u8         type;
  const u8*  body;
  wired_span tpd;
  wired_obuf ob = obuf_of(out, sizeof(out));

  CHECK(sflight_encrypted_extensions(wired_span_of(tp, sizeof(tp)), &ob));
  /* handshake header: type 0x08 and a length that matches ob.len. */
  CHECK(hs_parse(wired_span_of(out, ob.len), &type, &body_len) == 4);
  CHECK(type == QUIC_HS_ENCRYPTED_EXT);
  CHECK(4 + body_len == ob.len);

  /* body: 2-byte extensions length then the 0x39 extension. */
  body = out + 4;
  CHECK(((usz)body[0] << 8 | body[1]) == body_len - 2);
  used = tpext_decode(wired_span_of(body + 2, body_len - 2), &tpd);
  CHECK(used == body_len - 2);
  CHECK(tpd.n == sizeof(tp));
  CHECK(tpd.p[0] == 0xaa && tpd.p[4] == 0xee);

  /* a tight cap (one byte short) must be refused. */
  ob = obuf_of(out, ob.len - 1);
  CHECK(!sflight_encrypted_extensions(wired_span_of(tp, sizeof(tp)), &ob));
}
