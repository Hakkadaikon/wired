#include "app/qpack/qpackdyn/insert_encode.h"

#include "test.h"

/* RFC 9204 4.3.3: Insert With Literal Name, name "custom-key" (10 octets),
 * value "custom-value" (12 octets), both raw (H=0). First byte 010 + 5-bit
 * name length 10 = 0x4a; then the name; then a 7-bit string literal 0x0c +
 * value. */
static void test_insert_literal_golden(void) {
  const u8         name[]  = {'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y'};
  const u8         value[] = {'c', 'u', 's', 't', 'o', 'm',
                              '-', 'v', 'a', 'l', 'u', 'e'};
  u8               out[64];
  quic_qpack_field f = {
      quic_span_of(name, sizeof(name)), quic_span_of(value, sizeof(value))};
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  usz       w  = quic_qdyn_insert_literal(&f, &ob);
  CHECK(w == ob.len);
  CHECK(ob.len == 1 + 10 + 1 + 12);
  CHECK(out[0] == 0x4a);
  CHECK(out[1] == 'c' && out[10] == 'y');
  CHECK(out[11] == 0x0c);
  CHECK(out[12] == 'c' && out[23] == 'e');
}

/* A name length of 31 fills the 5-bit prefix and spills to a continuation. */
static void test_insert_literal_namelen_boundary(void) {
  u8       name[31];
  const u8 value[] = {'v'};
  u8       out[64];
  for (usz i = 0; i < sizeof(name); i++) name[i] = 'a';
  quic_qpack_field f = {
      quic_span_of(name, sizeof(name)), quic_span_of(value, 1)};
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  usz       w  = quic_qdyn_insert_literal(&f, &ob);
  CHECK(w == ob.len && ob.len == 2 + 31 + 2);
  CHECK(out[0] == 0x5f && out[1] == 0x00);
}

/* Too small a buffer fails cleanly. */
static void test_insert_literal_nofit(void) {
  const u8         name[]  = {'a', 'b'};
  const u8         value[] = {'c'};
  u8               out[2];
  quic_qpack_field f  = {quic_span_of(name, 2), quic_span_of(value, 1)};
  quic_obuf        ob = quic_obuf_of(out, sizeof(out));
  CHECK(quic_qdyn_insert_literal(&f, &ob) == 0);
}

void test_qpackdyn_insert_encode(void) {
  test_insert_literal_golden();
  test_insert_literal_namelen_boundary();
  test_insert_literal_nofit();
}
