#include "app/qpack/qpack/huffman.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/string.h"
#include "test.h"

static int hf_eq(const u8* a, usz alen, const char* b, usz blen) {
  if (alen != blen) return 0;
  for (usz i = 0; i < alen; i++)
    if (a[i] != (u8)b[i]) return 0;
  return 1;
}

/* RFC 7541 C.4.1: "www.example.com" Huffman-codes to these 12 octets. */
static void test_huffman_rfc_vector(void) {
  const u8  enc[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
                     0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
  u8        out[32];
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  CHECK(quic_qpack_huffman_decode(quic_span_of(enc, sizeof(enc)), &ob));
  CHECK(hf_eq(out, ob.len, "www.example.com", 15));
}

/* A curl/quiche-style user-agent and authority decode back to their text. */
static void test_huffman_curl_headers(void) {
  const u8  ua[]   = {0x25, 0xb6, 0x50, 0xc3, 0xcb, 0xba, 0xb8, 0x7f};
  const u8  host[] = {0x2f, 0x95, 0xc8, 0x7a, 0x7f};
  u8        out[32];
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  CHECK(quic_qpack_huffman_decode(quic_span_of(ua, sizeof(ua)), &ob));
  CHECK(hf_eq(out, ob.len, "curl/8.7.1", 10));
  CHECK(quic_qpack_huffman_decode(quic_span_of(host, sizeof(host)), &ob));
  CHECK(hf_eq(out, ob.len, "ex.com", 6));
}

/* RFC 7541 5.2: padding up to 7 bits of the EOS prefix (all ones) is dropped;
 * "/index" pads to a full final octet of 0x3f and decodes cleanly. */
static void test_huffman_padding(void) {
  const u8  enc[] = {0x60, 0xd5, 0x48, 0x5f, 0x3f};
  u8        out[16];
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  CHECK(quic_qpack_huffman_decode(quic_span_of(enc, sizeof(enc)), &ob));
  CHECK(hf_eq(out, ob.len, "/index", 6));
}

/* RFC 7541 5.2: a trailing pad that is not all-ones is a decoding error
 * (0x18 = 'a' code 00011 followed by non-ones padding 000). */
static void test_huffman_bad_padding(void) {
  const u8  enc[] = {0x18};
  u8        out[8];
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  CHECK(quic_qpack_huffman_decode(quic_span_of(enc, sizeof(enc)), &ob) == 0);
}

/* RFC 7541 5.2: padding of 8 or more bits, or an explicit EOS symbol, is an
 * error. 0xff*4 carries a 30-bit EOS code, never a valid string. */
static void test_huffman_eos_rejected(void) {
  const u8  enc[] = {0xff, 0xff, 0xff, 0xff};
  u8        out[8];
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  CHECK(quic_qpack_huffman_decode(quic_span_of(enc, sizeof(enc)), &ob) == 0);
}

/* A dst smaller than the decoded length fails rather than overflowing. */
static void test_huffman_overflow(void) {
  const u8  enc[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
                     0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
  u8        out[4];
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  CHECK(quic_qpack_huffman_decode(quic_span_of(enc, sizeof(enc)), &ob) == 0);
}

/* string_decode routes H=1 to the Huffman path; H=0 still copies raw. */
static void test_huffman_string_h1(void) {
  u8        buf[16] = {0x80 | 12, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
                       0x6b,      0xa0, 0xab, 0x90, 0xf4, 0xff};
  u8        out[32];
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  usz       r  = quic_qpack_string_decode(quic_span_of(buf, 13), &ob);
  CHECK(r == 13 && hf_eq(out, ob.len, "www.example.com", 15));

  const u8 raw[] = {'h', 'i'};
  u8       rbuf[8];
  usz      w = quic_qpack_string_encode(
      quic_mspan_of(rbuf, sizeof(rbuf)), quic_span_of(raw, 2));
  CHECK(w != 0);
  CHECK(quic_qpack_string_decode(quic_span_of(rbuf, w), &ob) == w);
  CHECK(hf_eq(out, ob.len, "hi", 2));
}

/* RFC 9204 4.5.6: a Literal Field Line With Literal Name whose H bit is set
 * carries a Huffman-coded name. curl/quiche emit such lines for fields not in
 * the static table; the name and value both decode. The line below is
 * 0x2c (001 0 1 100: litname, H=1, name length 4), the Huffman code for
 * ":path", then 0x82 (value length 2) and the Huffman code for "/p". */
static void test_huffman_litname_hname(void) {
  const u8            line[] = {0x2c, 0xb9, 0x58, 0xd3, 0x3f, 0x82, 0x62, 0xbf};
  u8                  nm[32], val[32];
  int                 never = 0;
  quic_qpack_fieldbuf fb    = {
      quic_obuf_of(nm, sizeof(nm)), quic_obuf_of(val, sizeof(val))};
  usz c = quic_qpack_literal_name_decode(
      quic_span_of(line, sizeof(line)), &never, &fb);
  CHECK(c == sizeof(line));
  CHECK(hf_eq(nm, fb.name.len, ":path", 5));
  CHECK(hf_eq(val, fb.value.len, "/p", 2));
}

void test_qpack_huffman(void) {
  test_huffman_rfc_vector();
  test_huffman_curl_headers();
  test_huffman_padding();
  test_huffman_bad_padding();
  test_huffman_eos_rejected();
  test_huffman_overflow();
  test_huffman_string_h1();
  test_huffman_litname_hname();
}
