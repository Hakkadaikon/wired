#include "test.h"

/* RFC 9204 4.5: :status 200 is in the static table, so the field section is
 * the 2-byte empty prefix followed by an Indexed Field Line (1Tiiiiii). */
static void test_field_encode_status_200(void) {
  u8         out[16];
  wired_obuf ob = {out, sizeof out, 0};
  CHECK(h3resp_encode_headers(200, 0, &ob) == 1);
  /* prefix: Required Insert Count 0, Delta Base 0. */
  CHECK(ob.len == 3);
  CHECK(out[0] == 0x00 && out[1] == 0x00);
  /* static index 25 (:status 200): 0x80|0x40|25 = 0xd9. */
  CHECK(out[2] == 0xd9);
}

/* A status absent from the static table is a Literal Field Line referencing
 * the :status name (static index 24) with the decimal value. */
static void test_field_encode_status_201(void) {
  u8            out[16];
  wired_obuf    ob = {out, sizeof out, 0};
  usz           pl;
  qpack_nameref r = {0, 0, 0};
  u8            val[8];
  wired_obuf    vb = obuf_of(val, sizeof val);
  CHECK(h3resp_encode_headers(201, 0, &ob) == 1);
  CHECK(out[0] == 0x00 && out[1] == 0x00);
  pl = qpack_literal_namref_decode(wired_span_of(out + 2, ob.len - 2), &r, &vb);
  CHECK(pl != 0);
  CHECK(r.is_static == 1 && r.index == 24);
  CHECK(vb.len == 3 && val[0] == '2' && val[1] == '0' && val[2] == '1');
}

/* A second in-table status confirms the Indexed index comes from the static
 * lookup, not a hard-coded 25: :status 404 is static index 27 -> 0x80|0x40|27.
 */
static void test_field_encode_status_404(void) {
  u8         out[16];
  wired_obuf ob = {out, sizeof out, 0};
  CHECK(h3resp_encode_headers(404, 0, &ob) == 1);
  CHECK(ob.len == 3 && out[0] == 0x00 && out[1] == 0x00);
  CHECK(out[2] == 0xdb);
}

/* Insufficient capacity fails without writing past the buffer. */
static void test_field_encode_overflow(void) {
  u8         out[2];
  wired_obuf ob = {out, sizeof out, 0};
  CHECK(h3resp_encode_headers(200, 0, &ob) == 0);
}

/* RFC 9204 4.5: :status 200 + content-type "text/html" (both in the static
 * table) is the 2-byte prefix, an Indexed Field Line for :status, then an
 * Indexed Field Line for content-type. */
static void test_field_encode_headers_content_type_indexed(void) {
  u8         out[16];
  wired_obuf ob = {out, sizeof out, 0};
  CHECK(h3resp_encode_headers(200, "text/css", &ob) == 1);
  CHECK(ob.len == 4);
  CHECK(out[0] == 0x00 && out[1] == 0x00);
  CHECK(out[2] == 0xd9); /* :status 200, static index 25 */
  /* content-type: text/css is static index 51 -> 0x80|0x40|51 = 0xf3. */
  CHECK(out[3] == 0xf3);
}

/* A content-type absent from the static table is a Literal Field Line
 * referencing the content-type name (static index 44, "content-type" value
 * ignored for a name-only reference). */
static void test_field_encode_headers_content_type_literal(void) {
  u8            out[32];
  wired_obuf    ob = {out, sizeof out, 0};
  usz           pl;
  qpack_nameref r = {0, 0, 0};
  u8            val[32];
  wired_obuf    vb = obuf_of(val, sizeof val);
  CHECK(h3resp_encode_headers(200, "text/javascript", &ob) == 1);
  pl = qpack_literal_namref_decode(wired_span_of(out + 3, ob.len - 3), &r, &vb);
  CHECK(pl != 0);
  CHECK(r.is_static == 1 && r.index == 44);
  CHECK(vb.len == 15);
}

/* content_type == 0 emits only the :status field line: 2-byte prefix + the
 * Indexed Field Line for :status 200 (static index 25), same as
 * test_field_encode_status_200. */
static void test_field_encode_headers_no_content_type(void) {
  u8         out[16];
  wired_obuf ob = {out, sizeof out, 0};
  CHECK(h3resp_encode_headers(200, 0, &ob) == 1);
  CHECK(ob.len == 3);
  CHECK(out[0] == 0x00 && out[1] == 0x00 && out[2] == 0xd9);
}

/* Insufficient capacity fails without writing past the buffer. */
static void test_field_encode_headers_overflow(void) {
  u8         out[3];
  wired_obuf ob = {out, sizeof out, 0};
  CHECK(h3resp_encode_headers(200, "text/css", &ob) == 0);
}

/* BOUNDARY: :status, content-type and 16 extra fields fill the section's
 * line table exactly; a 17th extra is refused rather than dropped. */
static void test_field_encode_extra_lines_bound(void) {
  static u8               out[2048];
  qpack_field             x[17];
  qpackenc_section_result r;
  wired_obuf              ob;
  for (usz i = 0; i < 17; i++) {
    x[i] = (qpack_field){
        wired_span_of((const u8*)"x-a", 3), wired_span_of((const u8*)"b", 1)};
  }
  ob = obuf_of(out, sizeof out);
  CHECK(h3resp_encode_headers_fields_qenc(200, "x/y", x, 16, 0, &r, &ob) == 1);
  ob = obuf_of(out, sizeof out);
  CHECK(h3resp_encode_headers_fields_qenc(200, "x/y", x, 17, 0, &r, &ob) == 0);
}

void test_field_encode(void) {
  test_field_encode_status_200();
  test_field_encode_status_201();
  test_field_encode_status_404();
  test_field_encode_overflow();
  test_field_encode_headers_content_type_indexed();
  test_field_encode_headers_content_type_literal();
  test_field_encode_headers_no_content_type();
  test_field_encode_headers_overflow();
  test_field_encode_extra_lines_bound();
}
