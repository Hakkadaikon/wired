#include "crypto/asymmetric/ecc/ecdsasig/der_int.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "test.h"

/* SEC1 C.5. Leading-bit-clear value encodes as 0x02 0x20 <32 bytes> verbatim.
 */
static void test_der_int_no_pad(void) {
  u8  v[32] = {0};
  u8  out[40];
  usz n = 0;
  v[0]  = 0x1b;
  v[31] = 0x7e;
  CHECK(quic_ecdsasig_encode_integer(v, out, sizeof(out), &n) == 1);
  CHECK(n == 34);
  CHECK(out[0] == QUIC_DER_INTEGER && out[1] == 0x20);
  CHECK(out[2] == 0x1b && out[33] == 0x7e);
}

/* RFC 5280. Top-bit-set leading octet gets a 0x00 prefix: length becomes 33. */
static void test_der_int_pad(void) {
  u8  v[32] = {0};
  u8  out[40];
  usz n = 0;
  v[0]  = 0xff;
  CHECK(quic_ecdsasig_encode_integer(v, out, sizeof(out), &n) == 1);
  CHECK(n == 35);
  CHECK(out[1] == 0x21 && out[2] == 0x00 && out[3] == 0xff);
}

/* SEC1 C.5. Redundant leading 0x00 octets are stripped to minimal form. */
static void test_der_int_strip(void) {
  u8  v[32] = {0};
  u8  out[40];
  usz n = 0;
  v[30] = 0x01;
  v[31] = 0x02;
  CHECK(quic_ecdsasig_encode_integer(v, out, sizeof(out), &n) == 1);
  CHECK(n == 4 && out[1] == 0x02 && out[2] == 0x01 && out[3] == 0x02);
}

/* SEC1 C.5. All-zero value encodes as a single 0x00 octet (not empty). */
static void test_der_int_zero(void) {
  u8  v[32] = {0};
  u8  out[40];
  usz n = 0;
  CHECK(quic_ecdsasig_encode_integer(v, out, sizeof(out), &n) == 1);
  CHECK(n == 3 && out[1] == 0x01 && out[2] == 0x00);
}

/* No room for the TLV is rejected. */
static void test_der_int_nofit(void) {
  u8  v[32] = {0};
  u8  out[3];
  usz n = 0;
  v[0]  = 0x7f;
  CHECK(quic_ecdsasig_encode_integer(v, out, sizeof(out), &n) == 0);
}

void test_ecdsasig_der_int(void) {
  test_der_int_no_pad();
  test_der_int_pad();
  test_der_int_strip();
  test_der_int_zero();
  test_der_int_nofit();
}
