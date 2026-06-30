#include "crypto/asymmetric/ecc/p256/p256_field.h"

#include "test.h"

static void p256_hb32(const char *hex, u8 out[32]) {
  for (usz i = 0; i < 32; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

/* a * a^-1 == 1 (mod p) and (mod n). */
static void test_p256_field_inv(void) {
  fe a, ai, prod, one = {1, 0, 0, 0};
  u8 ab[32];
  p256_hb32(
      "00112233445566778899aabbccddeeff00112233445566778899aabbccddee01", ab);
  quic_fp_from_be(a, ab);

  quic_fp_inv(ai, a, quic_p256_p);
  quic_fp_mul(prod, a, ai, quic_p256_p);
  CHECK(quic_fp_eq(prod, one));

  quic_fp_inv(ai, a, quic_p256_n);
  quic_fp_mul(prod, a, ai, quic_p256_n);
  CHECK(quic_fp_eq(prod, one));
}

/* add/sub round-trip: (a + b) - b == a (mod p). */
static void test_p256_field_addsub(void) {
  fe a, b, s, d;
  u8 ab[32], bb[32];
  p256_hb32(
      "0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff02", ab);
  p256_hb32(
      "00000000000000000000000000000000000000000000000000000000000000ff", bb);
  quic_fp_from_be(a, ab);
  quic_fp_from_be(b, bb);
  quic_fp_add(s, a, b, quic_p256_p);
  quic_fp_sub(d, s, b, quic_p256_p);
  CHECK(quic_fp_eq(d, a));
}

/* be round-trip: bytes -> fe -> bytes is identity. */
static void test_p256_field_bytes(void) {
  fe a;
  u8 in[32], out[32];
  p256_hb32(
      "0123456789abcdeffedcba98765432100011223344556677889900aabbccddee", in);
  quic_fp_from_be(a, in);
  quic_fp_to_be(out, a);
  for (usz i = 0; i < 32; i++) CHECK(out[i] == in[i]);
}

void test_p256_field(void) {
  test_p256_field_inv();
  test_p256_field_addsub();
  test_p256_field_bytes();
}
