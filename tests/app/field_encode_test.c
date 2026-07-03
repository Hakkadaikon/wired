#include "test.h"

/* RFC 9204 4.5: :status 200 is in the static table, so the field section is
 * the 2-byte empty prefix followed by an Indexed Field Line (1Tiiiiii). */
static void test_field_encode_status_200(void) {
  u8        out[16];
  quic_obuf ob = {out, sizeof out, 0};
  CHECK(quic_h3resp_encode_status(200, &ob) == 1);
  /* prefix: Required Insert Count 0, Delta Base 0. */
  CHECK(ob.len == 3);
  CHECK(out[0] == 0x00 && out[1] == 0x00);
  /* static index 25 (:status 200): 0x80|0x40|25 = 0xd9. */
  CHECK(out[2] == 0xd9);
}

/* A status absent from the static table is a Literal Field Line referencing
 * the :status name (static index 24) with the decimal value. */
static void test_field_encode_status_201(void) {
  u8                 out[16];
  quic_obuf          ob = {out, sizeof out, 0};
  usz                pl;
  quic_qpack_nameref r = {0, 0, 0};
  u8                 val[8];
  quic_obuf          vb = quic_obuf_of(val, sizeof val);
  CHECK(quic_h3resp_encode_status(201, &ob) == 1);
  CHECK(out[0] == 0x00 && out[1] == 0x00);
  pl = quic_qpack_literal_namref_decode(
      quic_span_of(out + 2, ob.len - 2), &r, &vb);
  CHECK(pl != 0);
  CHECK(r.is_static == 1 && r.index == 24);
  CHECK(vb.len == 3 && val[0] == '2' && val[1] == '0' && val[2] == '1');
}

/* A second in-table status confirms the Indexed index comes from the static
 * lookup, not a hard-coded 25: :status 404 is static index 27 -> 0x80|0x40|27.
 */
static void test_field_encode_status_404(void) {
  u8        out[16];
  quic_obuf ob = {out, sizeof out, 0};
  CHECK(quic_h3resp_encode_status(404, &ob) == 1);
  CHECK(ob.len == 3 && out[0] == 0x00 && out[1] == 0x00);
  CHECK(out[2] == 0xdb);
}

/* Insufficient capacity fails without writing past the buffer. */
static void test_field_encode_overflow(void) {
  u8        out[2];
  quic_obuf ob = {out, sizeof out, 0};
  CHECK(quic_h3resp_encode_status(200, &ob) == 0);
}

void test_field_encode(void) {
  test_field_encode_status_200();
  test_field_encode_status_201();
  test_field_encode_status_404();
  test_field_encode_overflow();
}
