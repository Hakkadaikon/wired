#include "test.h"

/* RFC 9204 4.5 / RFC 9114 4.3.1: :method GET, :scheme https and :path / are all
 * in the QPACK static table, so they encode as Indexed Field Lines; :authority
 * with a real value is not, so it is a Literal With Name Reference. */
static void test_pseudo_indexed_and_namref(void) {
  u8              out[64];
  wired_obuf      ob = {out, sizeof out, 0};
  const u8 *      m = (const u8*)"GET", *s = (const u8*)"https";
  const u8 *      p = (const u8*)"/", *a = (const u8*)"example.com";
  h3req_pseudo_in in = {
      wired_span_of(m, 3), wired_span_of(s, 5), wired_span_of(a, 11),
      wired_span_of(p, 1), wired_span_of(0, 0)};
  CHECK(h3req_enc_pseudo(&in, &ob) == 1);
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
  u8              out[64];
  wired_obuf      ob = {out, sizeof out, 0};
  const u8 *      m = (const u8*)"GET", *s = (const u8*)"https";
  const u8 *      p = (const u8*)"/", *a = (const u8*)"example.com";
  u64             idx       = 0;
  int             is_static = 0;
  usz             used;
  u8              val[32];
  wired_obuf      vb = obuf_of(val, sizeof val);
  qpack_nameref   nr = {0, 0, 0};
  const char *    nm, *vv;
  h3req_pseudo_in in = {
      wired_span_of(m, 3), wired_span_of(s, 5), wired_span_of(a, 11),
      wired_span_of(p, 1), wired_span_of(0, 0)};
  CHECK(h3req_enc_pseudo(&in, &ob) == 1);
  usz n = ob.len;
  /* first field line after the 2-byte prefix: Indexed :method GET (idx 17). */
  used = qpack_indexed_decode(wired_span_of(out + 2, n - 2), &idx, &is_static);
  CHECK(used == 1 && is_static == 1 && idx == 17);
  CHECK(qpack_static_get((usz)idx, &nm, &vv) == 1);
  CHECK(nm[0] == ':' && vv[0] == 'G');
  /* :authority literal: name index 0 resolves to ":authority", value echoed.
   * It follows prefix(2) + :method(1) + :scheme(1) at offset 4. */
  used = qpack_literal_namref_decode(wired_span_of(out + 4, n - 4), &nr, &vb);
  CHECK(used != 0 && nr.is_static == 1 && nr.index == 0);
  CHECK(vb.len == 11 && val[0] == 'e' && val[10] == 'm');
  CHECK(qpack_static_get((usz)nr.index, &nm, &vv) == 1);
  CHECK(nm[1] == 'a'); /* ":authority" */
}

/* Insufficient capacity fails without overrun. */
static void test_pseudo_overflow(void) {
  u8              out[3];
  wired_obuf      ob = {out, sizeof out, 0};
  const u8 *      m = (const u8*)"GET", *s = (const u8*)"https";
  const u8 *      p = (const u8*)"/", *a = (const u8*)"example.com";
  h3req_pseudo_in in = {
      wired_span_of(m, 3), wired_span_of(s, 5), wired_span_of(a, 11),
      wired_span_of(p, 1), wired_span_of(0, 0)};
  CHECK(h3req_enc_pseudo(&in, &ob) == 0);
}

/* Wrap a QPACK field section fs into a HEADERS frame inside a STREAM frame,
 * mirroring the wire shape wired_h3reqdrive_recv_get expects. */
static usz wrap_stream(const u8* fs, usz fs_len, u8* out, usz cap) {
  u8         h3[192];
  wired_obuf h3b = obuf_of(h3, sizeof h3);
  CHECK(h3_frame_put(&h3b, H3_FRAME_HEADERS, wired_span_of(fs, fs_len)) > 0);
  stream_frame sf = {0, 0, h3b.len, h3, 1};
  return frame_put_stream(out, cap, &sf);
}

/* RFC 9220 3: an Extended CONNECT (:method=CONNECT, :scheme=https,
 * :protocol=webtransport-h3) encoded by h3req_enc_pseudo round-trips
 * through the existing receive-side parser (request_drive.c classify_line).
 */
static void test_pseudo_protocol_roundtrip(void) {
  static const u8 m[] = "CONNECT", s[] = "https", a[] = "host", p[] = "/wt",
                  proto[] = "webtransport-h3";
  h3req_pseudo_in in      = {
      wired_span_of(m, sizeof m - 1), wired_span_of(s, sizeof s - 1),
      wired_span_of(a, sizeof a - 1), wired_span_of(p, sizeof p - 1),
      wired_span_of(proto, sizeof proto - 1)};
  u8         fs[128];
  wired_obuf fsb = obuf_of(fs, sizeof fs);
  CHECK(h3req_enc_pseudo(&in, &fsb) == 1);

  u8  stream[256];
  usz n = wrap_stream(fs, fsb.len, stream, sizeof stream);
  CHECK(n > 0);

  u8                   scratch[128];
  wired_h3reqdrive_req r = {0};
  CHECK(
      wired_h3reqdrive_recv_get(
          wired_span_of(stream, n), wired_mspan_of(scratch, sizeof scratch),
          &r) == 1);
  CHECK(r.protocol_len == sizeof proto - 1);
  for (usz i = 0; i < sizeof proto - 1; i++) CHECK(r.protocol[i] == proto[i]);
  CHECK(r.method_len == sizeof m - 1);
  CHECK(r.scheme_len == sizeof s - 1);
}

/* An empty :protocol span omits the field line entirely: a plain request
 * (no Extended CONNECT) does not regress. */
static void test_pseudo_protocol_omitted(void) {
  static const u8 m[] = "GET", s[] = "https", a[] = "host", p[] = "/";
  h3req_pseudo_in in = {
      wired_span_of(m, sizeof m - 1), wired_span_of(s, sizeof s - 1),
      wired_span_of(a, sizeof a - 1), wired_span_of(p, sizeof p - 1),
      wired_span_of(0, 0)};
  u8         fs_with[128], fs_without[128];
  wired_obuf a_ob = obuf_of(fs_with, sizeof fs_with);
  CHECK(h3req_enc_pseudo(&in, &a_ob) == 1);

  /* Same fields via the 4-field struct (no protocol member set at all,
   * relying on the struct's zero-initialized tail) produce identical bytes. */
  h3req_pseudo_in in2 = {
      in.method, in.scheme, in.authority, in.path, wired_span_of(0, 0)};
  wired_obuf b_ob = obuf_of(fs_without, sizeof fs_without);
  CHECK(h3req_enc_pseudo(&in2, &b_ob) == 1);

  CHECK(a_ob.len == b_ob.len);
  for (usz i = 0; i < a_ob.len; i++) CHECK(fs_with[i] == fs_without[i]);
}

void test_pseudo_encode(void) {
  test_pseudo_indexed_and_namref();
  test_pseudo_roundtrip();
  test_pseudo_overflow();
  test_pseudo_protocol_roundtrip();
  test_pseudo_protocol_omitted();
}
