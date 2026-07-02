#include "test.h"

static void test_certreq_wire_structure(void) {
  u8        sa[4] = {0x04, 0x03, 0x08, 0x04};
  u8        out[64];
  quic_obuf o = quic_obuf_of(out, sizeof(out));
  CHECK(quic_certreq_build(quic_span_of(sa, sizeof(sa)), &o) == 1);
  /* handshake type 0x0d, then 24-bit body length. RFC 8446 4.3.2. */
  CHECK(out[0] == 0x0d);
  CHECK(((usz)out[1] << 16 | (usz)out[2] << 8 | out[3]) == o.len - 4);
  /* empty certificate_request_context. */
  CHECK(out[4] == 0);
  /* extensions block length covers a single signature_algorithms extension:
   * type(2) extlen(2) listlen(2) + 4 schemes = 10 bytes. */
  CHECK(((usz)out[5] << 8 | out[6]) == 10);
  CHECK(((u16)out[7] << 8 | out[8]) == 0x000d); /* signature_algorithms */
  CHECK(((u16)out[11] << 8 | out[12]) == 4);    /* scheme list length */
  CHECK(out[13] == 0x04 && out[14] == 0x03);
}

static void test_certreq_roundtrip(void) {
  u8           sa[6] = {0x04, 0x03, 0x08, 0x04, 0x08, 0x07};
  u8           out[64];
  quic_obuf    o = quic_obuf_of(out, sizeof(out));
  quic_certreq cr;
  CHECK(quic_certreq_build(quic_span_of(sa, sizeof(sa)), &o) == 1);
  CHECK(quic_certreq_parse(quic_span_of(out, o.len), &cr) == 1);
  CHECK(cr.ctx.n == 0);
  CHECK(cr.sig_algs.n == sizeof(sa));
  for (usz i = 0; i < sizeof(sa); i++) CHECK(cr.sig_algs.p[i] == sa[i]);
}

static void test_certreq_build_no_room(void) {
  u8        sa[4] = {0x04, 0x03, 0x08, 0x04};
  u8        out[8];
  quic_obuf o = quic_obuf_of(out, sizeof(out));
  CHECK(quic_certreq_build(quic_span_of(sa, sizeof(sa)), &o) == 0);
}

static void test_certreq_parse_wrong_type(void) {
  u8           sa[4] = {0x04, 0x03, 0x08, 0x04};
  u8           out[64];
  quic_obuf    o = quic_obuf_of(out, sizeof(out));
  quic_certreq cr;
  CHECK(quic_certreq_build(quic_span_of(sa, sizeof(sa)), &o) == 1);
  out[0] = 0x0b; /* Certificate, not CertificateRequest */
  CHECK(quic_certreq_parse(quic_span_of(out, o.len), &cr) == 0);
}

static void test_certreq_parse_truncated(void) {
  u8           sa[4] = {0x04, 0x03, 0x08, 0x04};
  u8           out[64];
  quic_obuf    o = quic_obuf_of(out, sizeof(out));
  quic_certreq cr;
  CHECK(quic_certreq_build(quic_span_of(sa, sizeof(sa)), &o) == 1);
  CHECK(quic_certreq_parse(quic_span_of(out, o.len - 1), &cr) == 0);
}

static void test_certreq_parse_missing_sig_algs(void) {
  u8           msg[16];
  quic_certreq cr;
  usz          off = quic_hs_begin(msg, sizeof(msg), 0x0d);
  msg[off]         = 0; /* empty context */
  msg[off + 1]     = 0; /* extensions length 0 */
  msg[off + 2]     = 0;
  quic_hs_finish(msg, off + 3);
  CHECK(quic_certreq_parse(quic_span_of(msg, off + 3), &cr) == 0);
}

void test_certreq(void) {
  test_certreq_wire_structure();
  test_certreq_roundtrip();
  test_certreq_build_no_room();
  test_certreq_parse_wrong_type();
  test_certreq_parse_truncated();
  test_certreq_parse_missing_sig_algs();
}
