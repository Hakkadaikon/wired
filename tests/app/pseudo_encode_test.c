#include "test.h"

/* RFC 9204 4.5 / RFC 9114 4.3.1: :method GET, :scheme https and :path / are all
 * in the QPACK static table, so they encode as Indexed Field Lines; :authority
 * with a real value is not, so it is a Literal With Name Reference. */
static void test_pseudo_indexed_and_namref(void) {
  u8                   out[64];
  quic_obuf            ob = {out, sizeof out, 0};
  const u8 *           m = (const u8*)"GET", *s = (const u8*)"https";
  const u8 *           p = (const u8*)"/", *a = (const u8*)"example.com";
  quic_h3req_pseudo_in in = {
      quic_span_of(m, 3), quic_span_of(s, 5), quic_span_of(a, 11),
      quic_span_of(p, 1)};
  CHECK(quic_h3req_enc_pseudo(&in, &ob) == 1);
  /* empty prefix (RIC 0, Base 0). */
  CHECK(out[0] == 0x00 && out[1] == 0x00);
  /* :method GET = static 17 -> 0x80|0x40|17, :scheme https = 23, :path / = 1.
   */
  CHECK(out[2] == 0xd1);
  CHECK(out[3] == 0xd7);
  /* :authority "example.com" is a literal name reference (01NTiiii). */
  CHECK((out[4] & 0xf0) == 0x50);
}

/* Round-trip: decode the Indexed and Literal field lines back and confirm the
 * pseudo-headers resolve to their static names/values. */
static void test_pseudo_roundtrip(void) {
  u8                   out[64];
  quic_obuf            ob = {out, sizeof out, 0};
  const u8 *           m = (const u8*)"GET", *s = (const u8*)"https";
  const u8 *           p = (const u8*)"/", *a = (const u8*)"example.com";
  u64                  idx       = 0;
  int                  is_static = 0;
  usz                  used;
  u8                   val[32];
  quic_obuf            vb = quic_obuf_of(val, sizeof val);
  quic_qpack_nameref   nr = {0, 0, 0};
  const char *         nm, *vv;
  quic_h3req_pseudo_in in = {
      quic_span_of(m, 3), quic_span_of(s, 5), quic_span_of(a, 11),
      quic_span_of(p, 1)};
  CHECK(quic_h3req_enc_pseudo(&in, &ob) == 1);
  usz n = ob.len;
  /* first field line after the 2-byte prefix: Indexed :method GET (idx 17). */
  used =
      quic_qpack_indexed_decode(quic_span_of(out + 2, n - 2), &idx, &is_static);
  CHECK(used == 1 && is_static == 1 && idx == 17);
  CHECK(quic_qpack_static_get((usz)idx, &nm, &vv) == 1);
  CHECK(nm[0] == ':' && vv[0] == 'G');
  /* :authority literal: name index 0 resolves to ":authority", value echoed.
   * It follows prefix(2) + :method(1) + :scheme(1) at offset 4. */
  used =
      quic_qpack_literal_namref_decode(quic_span_of(out + 4, n - 4), &nr, &vb);
  CHECK(used != 0 && nr.is_static == 1 && nr.index == 0);
  CHECK(vb.len == 11 && val[0] == 'e' && val[10] == 'm');
  CHECK(quic_qpack_static_get((usz)nr.index, &nm, &vv) == 1);
  CHECK(nm[1] == 'a'); /* ":authority" */
}

/* Insufficient capacity fails without overrun. */
static void test_pseudo_overflow(void) {
  u8                   out[3];
  quic_obuf            ob = {out, sizeof out, 0};
  const u8 *           m = (const u8*)"GET", *s = (const u8*)"https";
  const u8 *           p = (const u8*)"/", *a = (const u8*)"example.com";
  quic_h3req_pseudo_in in = {
      quic_span_of(m, 3), quic_span_of(s, 5), quic_span_of(a, 11),
      quic_span_of(p, 1)};
  CHECK(quic_h3req_enc_pseudo(&in, &ob) == 0);
}

void test_pseudo_encode(void) {
  test_pseudo_indexed_and_namref();
  test_pseudo_roundtrip();
  test_pseudo_overflow();
}
