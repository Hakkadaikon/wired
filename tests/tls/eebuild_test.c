#include "tls/handshake/roles/eebuild/eebuild.h"

#include "test.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/tpext.h"

/* RFC 8446 4.3.1 / RFC 7301 / RFC 9001 8.1-8.2: EncryptedExtensions carries
 * BOTH the negotiated ALPN ("h3") and quic_transport_parameters (0x39). Both
 * extensions and the message/block framing must read back. */
void test_eebuild(void) {
  const u8  tp[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  u8        out[128];
  usz       body_len, used;
  u8        type;
  const u8* body;
  quic_span tpd;
  quic_obuf ob = quic_obuf_of(out, sizeof(out));

  CHECK(quic_eebuild_encrypted_extensions(
      QUIC_SALPN_H3, quic_span_of(tp, sizeof(tp)), &ob));

  /* handshake header: type 0x08, length consistent with ob.len. */
  CHECK(quic_hs_parse(quic_span_of(out, ob.len), &type, &body_len) == 4);
  CHECK(type == QUIC_HS_ENCRYPTED_EXT);
  CHECK(4 + body_len == ob.len);

  /* body: 2-byte extensions length, then ALPN(9) then the 0x39 extension. */
  body = out + 4;
  CHECK(((usz)body[0] << 8 | body[1]) == body_len - 2);

  /* ALPN extension first: type 0x0010 and the "h3" ProtocolNameList. */
  CHECK(((usz)body[2] << 8 | body[3]) == QUIC_SALPN_EXT_TYPE);
  CHECK(quic_salpn_select_h3(body + 6, 5)); /* ext_data: list_len + "h3" */

  /* quic_transport_parameters follows the 9-byte ALPN extension. */
  used = quic_tpext_decode(quic_span_of(body + 2 + 9, body_len - 2 - 9), &tpd);
  CHECK(used == body_len - 2 - 9);
  CHECK(tpd.n == sizeof(tp));
  CHECK(tpd.p[0] == 0xaa && tpd.p[4] == 0xee);

  /* a tight cap (one byte short) must be refused. */
  ob = quic_obuf_of(out, ob.len - 1);
  CHECK(!quic_eebuild_encrypted_extensions(
      QUIC_SALPN_H3, quic_span_of(tp, sizeof(tp)), &ob));
}

/* hq-interop selected: the ALPN extension carries "hq-interop" (17 bytes)
 * instead of "h3" (9), and the 0x39 extension still follows it. */
void test_eebuild_selects_hq(void) {
  const u8  tp[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  u8        out[128];
  usz       body_len;
  u8        type;
  const u8* body;
  quic_obuf ob = quic_obuf_of(out, sizeof(out));

  CHECK(quic_eebuild_encrypted_extensions(
      QUIC_SALPN_HQ, quic_span_of(tp, sizeof(tp)), &ob));
  CHECK(quic_hs_parse(quic_span_of(out, ob.len), &type, &body_len) == 4);
  body = out + 4;
  CHECK(((usz)body[2] << 8 | body[3]) == QUIC_SALPN_EXT_TYPE);
  CHECK(quic_salpn_select_hq(body + 6, 13)); /* ext_data: list_len + name */
  CHECK(!quic_salpn_select_h3(body + 6, 13));
}

/* No protocol negotiated (QUIC_SALPN_NONE) must fail closed -- nothing is
 * built, matching the safe-failure this task's ALPN negotiation relies on. */
void test_eebuild_rejects_no_negotiation(void) {
  const u8  tp[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  u8        out[128];
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  CHECK(!quic_eebuild_encrypted_extensions(
      QUIC_SALPN_NONE, quic_span_of(tp, sizeof(tp)), &ob));
}
