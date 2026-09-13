#include "app/qpack/qpack/literal.h"

#include "test.h"

/* RFC 9204 4.5.4: N=0,T=1,index=1 (01010001=0x51), value "/" (0x01 0x2f). */
static void test_literal_namref_golden(void) {
  const u8      v[] = {'/'};
  u8            buf[8];
  qpack_nameref er = {1, 1, 0};
  usz           w  = qpack_literal_namref_encode(
      wired_mspan_of(buf, sizeof(buf)), &er, wired_span_of(v, 1));
  CHECK(w == 3 && buf[0] == 0x51 && buf[1] == 0x01 && buf[2] == 0x2f);

  qpack_nameref dr;
  u8            out[8];
  wired_obuf    ob = obuf_of(out, sizeof(out));
  usz r = qpack_literal_namref_decode(wired_span_of(buf, w), &dr, &ob);
  CHECK(r == w && dr.index == 1 && dr.is_static == 1 && dr.never == 0);
  CHECK(ob.len == 1 && out[0] == '/');
}

/* Never-indexed and dynamic-table flags round-trip in the name-reference form.
 */
static void test_literal_namref_flags(void) {
  const u8      v[] = {'a', 'b'};
  u8            buf[8];
  qpack_nameref er = {3, 0, 1};
  usz           w  = qpack_literal_namref_encode(
      wired_mspan_of(buf, sizeof(buf)), &er, wired_span_of(v, 2));
  /* 01NTiiii: N=1,T=0,index=3 -> 0110 0011 = 0x63. */
  CHECK(w != 0 && buf[0] == 0x63);

  qpack_nameref dr;
  u8            out[8];
  wired_obuf    ob = obuf_of(out, sizeof(out));
  usz r = qpack_literal_namref_decode(wired_span_of(buf, w), &dr, &ob);
  CHECK(r == w && dr.index == 3 && dr.is_static == 0 && dr.never == 1);
  CHECK(ob.len == 2 && out[0] == 'a' && out[1] == 'b');
}

/* A first byte not matching 01xxxxxx is not a name-reference field line. */
static void test_literal_namref_reject(void) {
  u8            bad = 0x80;
  qpack_nameref dr;
  u8            out[8];
  wired_obuf    ob = obuf_of(out, sizeof(out));
  CHECK(qpack_literal_namref_decode(wired_span_of(&bad, 1), &dr, &ob) == 0);
}

/* RFC 9204 4.5.6: N=0,H=0,name "x" (00100001=0x21, 0x78), value "y". */
static void test_literal_name_golden(void) {
  const u8    nm[] = {'x'};
  const u8    v[]  = {'y'};
  u8          buf[8];
  qpack_field ef = {wired_span_of(nm, 1), wired_span_of(v, 1)};
  usz w = qpack_literal_name_encode(wired_mspan_of(buf, sizeof(buf)), 0, &ef);
  CHECK(w == 4 && buf[0] == 0x21 && buf[1] == 0x78);
  CHECK(buf[2] == 0x01 && buf[3] == 0x79);

  int            nv;
  u8             outn[8], outv[8];
  qpack_fieldbuf fb = {
      obuf_of(outn, sizeof(outn)), obuf_of(outv, sizeof(outv))};
  usz r = qpack_literal_name_decode(wired_span_of(buf, w), &nv, &fb);
  CHECK(r == w && nv == 0 && fb.name.len == 1 && outn[0] == 'x');
  CHECK(fb.value.len == 1 && outv[0] == 'y');
}

/* A name length of 7 fills the 3-bit prefix, spilling the length integer. */
static void test_literal_name_prefix_boundary(void) {
  const u8    nm[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};
  const u8    v[]  = {'z'};
  u8          buf[16];
  qpack_field ef = {wired_span_of(nm, 7), wired_span_of(v, 1)};
  usz w = qpack_literal_name_encode(wired_mspan_of(buf, sizeof(buf)), 0, &ef);
  /* 001NHiii with iii=111 then a 0x00 continuation byte for 7-7=0. */
  CHECK(w != 0 && buf[0] == 0x27 && buf[1] == 0x00);

  int            nv;
  u8             outn[8], outv[8];
  qpack_fieldbuf fb = {
      obuf_of(outn, sizeof(outn)), obuf_of(outv, sizeof(outv))};
  usz r = qpack_literal_name_decode(wired_span_of(buf, w), &nv, &fb);
  CHECK(r == w && fb.name.len == 7 && outn[6] == 'g');
  CHECK(fb.value.len == 1 && outv[0] == 'z');
}

/* H=1 (Huffman name) is rejected; so is a non-001 pattern. */
static void test_literal_name_reject(void) {
  u8             huff  = 0x28; /* 001 0 1 000: H set */
  u8             wrong = 0x40;
  int            nv;
  u8             outn[8], outv[8];
  qpack_fieldbuf fb = {
      obuf_of(outn, sizeof(outn)), obuf_of(outv, sizeof(outv))};
  CHECK(qpack_literal_name_decode(wired_span_of(&huff, 1), &nv, &fb) == 0);
  CHECK(qpack_literal_name_decode(wired_span_of(&wrong, 1), &nv, &fb) == 0);
}

/* RFC 9204 4.5.5: N=0, index=0 (0000 0 000=0x00), value "x" (0x01 0x78). */
static void test_literal_postbase_golden(void) {
  const u8          v[] = {'x'};
  u8                buf[8];
  qpack_postbaseref er = {0, 0};
  usz               w  = qpack_literal_postbase_encode(
      wired_mspan_of(buf, sizeof(buf)), &er, wired_span_of(v, 1));
  CHECK(w == 3 && buf[0] == 0x00 && buf[1] == 0x01 && buf[2] == 0x78);

  qpack_postbaseref dr;
  u8                out[8];
  wired_obuf        ob = obuf_of(out, sizeof(out));
  usz r = qpack_literal_postbase_decode(wired_span_of(buf, w), &dr, &ob);
  CHECK(r == w && dr.index == 0 && dr.never == 0);
  CHECK(ob.len == 1 && out[0] == 'x');
}

/* The never-indexed flag and a non-zero post-Base index round-trip. */
static void test_literal_postbase_flags(void) {
  const u8          v[] = {'a', 'b'};
  u8                buf[8];
  qpack_postbaseref er = {3, 1};
  usz               w  = qpack_literal_postbase_encode(
      wired_mspan_of(buf, sizeof(buf)), &er, wired_span_of(v, 2));
  /* 0000Niii: N=1, index=3 -> 0000 1011 = 0x0B. */
  CHECK(w != 0 && buf[0] == 0x0B);

  qpack_postbaseref dr;
  u8                out[8];
  wired_obuf        ob = obuf_of(out, sizeof(out));
  usz r = qpack_literal_postbase_decode(wired_span_of(buf, w), &dr, &ob);
  CHECK(r == w && dr.index == 3 && dr.never == 1);
  CHECK(ob.len == 2 && out[0] == 'a' && out[1] == 'b');
}

/* A first byte outside the 0000xxxx pattern is not a post-Base name
 * reference. */
static void test_literal_postbase_reject(void) {
  u8                bad = 0x80; /* Indexed Field Line */
  qpack_postbaseref dr;
  u8                out[8];
  wired_obuf        ob = obuf_of(out, sizeof(out));
  CHECK(qpack_literal_postbase_decode(wired_span_of(&bad, 1), &dr, &ob) == 0);
}

/* Pinning: CVE-2024-34161-class oob-read -- litname_bounds and str_value must
 * reject a name/value length that would read past the input span, never
 * disclosing adjacent memory (V-0433). */
static void test_qpack_literal_name_decode_truncated_rejected(void) {
  int            nv;
  u8             outn[8], outv[8];
  qpack_fieldbuf fb = {
      obuf_of(outn, sizeof(outn)), obuf_of(outv, sizeof(outv))};

  /* header claims a 7-byte name but only 2 bytes follow the first byte. */
  u8 buf[3] = {0x27, 'a', 'b'};
  CHECK(
      qpack_literal_name_decode(wired_span_of(buf, sizeof buf), &nv, &fb) == 0);

  /* header claims a huge (multi-byte continuation) name length that can
   * never fit any realistic buffer. */
  u8 buf2[4] = {0x27, 0xff, 0xff, 0x7f};
  CHECK(
      qpack_literal_name_decode(wired_span_of(buf2, sizeof buf2), &nv, &fb) ==
      0);
}

/* Pinning: RFC 9204 7.1.3 -- the never-indexed (N) bit must be preserved
 * exactly as decoded across all three literal forms, so a caller can honor
 * "MUST NOT re-encode ... without the flag" (V-0472). */
static void test_qpack_literal_never_bit_preserved(void) {
  const u8      v[] = {'z'};
  u8            buf[8];
  qpack_nameref er = {5, 0, 1}; /* never=1 */
  usz           w  = qpack_literal_namref_encode(
      wired_mspan_of(buf, sizeof(buf)), &er, wired_span_of(v, 1));
  qpack_nameref dr;
  u8            out[8];
  wired_obuf    ob = obuf_of(out, sizeof(out));
  CHECK(qpack_literal_namref_decode(wired_span_of(buf, w), &dr, &ob) == w);
  CHECK(dr.never == 1);

  qpack_field nf = {wired_span_of((const u8*)"n", 1), wired_span_of(v, 1)};
  u8          nbuf[8];
  usz         nw =
      qpack_literal_name_encode(wired_mspan_of(nbuf, sizeof(nbuf)), 1, &nf);
  int            nv;
  u8             outn[8], outv[8];
  qpack_fieldbuf fb = {
      obuf_of(outn, sizeof(outn)), obuf_of(outv, sizeof(outv))};
  CHECK(qpack_literal_name_decode(wired_span_of(nbuf, nw), &nv, &fb) == nw);
  CHECK(nv == 1);

  qpack_postbaseref pr = {2, 1};
  u8                pbuf[8];
  usz               pw = qpack_literal_postbase_encode(
      wired_mspan_of(pbuf, sizeof(pbuf)), &pr, wired_span_of(v, 1));
  qpack_postbaseref pdr;
  u8                pout[8];
  wired_obuf        pob = obuf_of(pout, sizeof(pout));
  CHECK(
      qpack_literal_postbase_decode(wired_span_of(pbuf, pw), &pdr, &pob) == pw);
  CHECK(pdr.never == 1);
}

/* Pinning: RFC 9204 7.4/4.5 -- a value larger than the caller's scratch can
 * decode MUST be a hard decode failure for the whole field line, never a
 * truncated partial value (V-0478). qpack_literal_name_decode's value half
 * goes through qpack_string_decode, which fails closed once dst->cap is
 * exceeded; that failure propagates to the whole line, not just the value
 * half. */
static void test_qpack_oversized_value_rejects_whole_line(void) {
  const u8 nm[] = {'n'};
  u8       big_value[64];
  for (usz i = 0; i < sizeof big_value; i++) big_value[i] = (u8)('a' + i % 26);
  u8          buf[128];
  qpack_field ef = {
      wired_span_of(nm, 1), wired_span_of(big_value, sizeof big_value)};
  usz w = qpack_literal_name_encode(wired_mspan_of(buf, sizeof(buf)), 0, &ef);
  CHECK(w != 0);

  int            nv;
  u8             outn[8], outv[64]; /* value cap (8) far smaller than 64 */
  qpack_fieldbuf fb = {obuf_of(outn, sizeof(outn)), obuf_of(outv, 8)};
  CHECK(qpack_literal_name_decode(wired_span_of(buf, w), &nv, &fb) == 0);
  /* the whole line is rejected: no truncated partial value was left set. */
  CHECK(fb.value.len == 0);
}

void test_literal(void) {
  test_literal_namref_golden();
  test_literal_namref_flags();
  test_literal_namref_reject();
  test_literal_name_golden();
  test_literal_name_prefix_boundary();
  test_literal_name_reject();
  test_literal_postbase_golden();
  test_literal_postbase_flags();
  test_literal_postbase_reject();
  test_qpack_literal_name_decode_truncated_rejected();
  test_qpack_literal_never_bit_preserved();
  test_qpack_oversized_value_rejects_whole_line();
}
