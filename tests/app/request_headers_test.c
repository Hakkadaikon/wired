#include "test.h"

/* RFC 9114 4.3.1: a GET request field section is the empty prefix followed by
 * :method GET (static 17), :scheme https (23), :authority (literal), :path (1
 * when "/"). */
static void test_get_field_section(void) {
  u8               out[64];
  wired_obuf       ob   = {out, sizeof out, 0};
  const u8 *       path = (const u8*)"/", *authority = (const u8*)"example.com";
  u64              idx       = 0;
  int              is_static = 0;
  usz              used;
  u8               val[32];
  wired_obuf       vb  = obuf_of(val, sizeof val);
  qpack_nameref    nr  = {0, 0, 0};
  h3req_headers_in hin = {wired_span_of(path, 1), wired_span_of(authority, 11)};
  CHECK(h3req_enc_get(&hin, &ob) == 1);
  usz n = ob.len;
  CHECK(out[0] == 0x00 && out[1] == 0x00);
  /* :method GET indexed. */
  used = qpack_indexed_decode(wired_span_of(out + 2, n - 2), &idx, &is_static);
  CHECK(used == 1 && idx == 17);
  /* :scheme https indexed. */
  used = qpack_indexed_decode(wired_span_of(out + 3, n - 3), &idx, &is_static);
  CHECK(used == 1 && idx == 23);
  /* :authority literal name reference (idx 0), value echoed. */
  used = qpack_literal_namref_decode(wired_span_of(out + 4, n - 4), &nr, &vb);
  CHECK(used != 0 && nr.index == 0 && vb.len == 11 && val[0] == 'e');
  /* :path / indexed (idx 1). */
  used = qpack_indexed_decode(
      wired_span_of(out + 4 + used, n - 4 - used), &idx, &is_static);
  CHECK(used == 1 && idx == 1);
}

/* Insufficient capacity fails. */
static void test_get_overflow(void) {
  u8               out[3];
  wired_obuf       ob   = {out, sizeof out, 0};
  const u8 *       path = (const u8*)"/", *authority = (const u8*)"example.com";
  h3req_headers_in hin = {wired_span_of(path, 1), wired_span_of(authority, 11)};
  CHECK(h3req_enc_get(&hin, &ob) == 0);
}

void test_request_headers(void) {
  test_get_field_section();
  test_get_overflow();
}
