#include "app/qpack/qpackdyn/insert_encode.h"

#include "test.h"

/* RFC 9204 4.3.3: Insert With Literal Name, name "custom-key" (10 octets),
 * value "custom-value" (12 octets). The name Huffman-coded is 8 octets (RFC
 * 7541 C.4.3's 25a8 49e9 5ba9 7d7f), so first byte 01 H=1 + 5-bit length 8
 * = 0x68; then the value as a Huffman string literal (H=1, 9 octets: 0x89,
 * C.4.3's 25a8 49e9 5bb8 e8b4 bf). */
static void test_insert_literal_golden(void) {
  const u8    name[]  = {'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y'};
  const u8    value[] = {'c', 'u', 's', 't', 'o', 'm',
                         '-', 'v', 'a', 'l', 'u', 'e'};
  u8          out[64];
  qpack_field f = {
      wired_span_of(name, sizeof(name)), wired_span_of(value, sizeof(value))};
  wired_obuf ob = obuf_of(out, sizeof(out));
  usz        w  = qdyn_insert_literal(&f, &ob);
  CHECK(w == ob.len);
  CHECK(ob.len == 1 + 8 + 1 + 9);
  CHECK(out[0] == 0x68);
  CHECK(out[1] == 0x25 && out[2] == 0xa8 && out[7] == 0x7d && out[8] == 0x7f);
  CHECK(out[9] == 0x89);
  CHECK(out[10] == 0x25 && out[18] == 0xbf);
}

/* A name length of 31 fills the 5-bit prefix and spills to a continuation.
 * 'X' has an 8-bit Huffman code, so the name stays raw (H=0). */
static void test_insert_literal_namelen_boundary(void) {
  u8       name[31];
  const u8 value[] = {'v'};
  u8       out[64];
  for (usz i = 0; i < sizeof(name); i++) {
    name[i] = 'X';
  }
  qpack_field f  = {wired_span_of(name, sizeof(name)), wired_span_of(value, 1)};
  wired_obuf  ob = obuf_of(out, sizeof(out));
  usz         w  = qdyn_insert_literal(&f, &ob);
  CHECK(w == ob.len && ob.len == 2 + 31 + 2);
  CHECK(out[0] == 0x5f && out[1] == 0x00);
}

/* Too small a buffer fails cleanly. */
static void test_insert_literal_nofit(void) {
  const u8    name[]  = {'a', 'b'};
  const u8    value[] = {'c'};
  u8          out[2];
  qpack_field f  = {wired_span_of(name, 2), wired_span_of(value, 1)};
  wired_obuf  ob = obuf_of(out, sizeof(out));
  CHECK(qdyn_insert_literal(&f, &ob) == 0);
}

void test_qpackdyn_insert_encode(void) {
  test_insert_literal_golden();
  test_insert_literal_namelen_boundary();
  test_insert_literal_nofit();
}
