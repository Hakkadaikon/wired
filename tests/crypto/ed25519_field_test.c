#include "crypto/asymmetric/ecc/ed25519/ed25519_field.h"

#include "test.h"

/* RFC 8032 Section 5.1.3 point decoding boundary cases. quic_ed_ge_decode is
 * internal (not exposed via ed25519.h) but is exercised directly here since
 * it is the sole place these three MUST-fail conditions are enforced; going
 * through quic_ed25519_verify would conflate a decode rejection with an
 * unrelated signature mismatch. */

static u8 edf_hexnib(char c) { return (u8)(c <= '9' ? c - '0' : c - 'a' + 10); }

static void edf_hexbytes(const char* hex, u8* out, usz n) {
  for (usz i = 0; i < n; i++)
    out[i] = (u8)((edf_hexnib(hex[i * 2]) << 4) | edf_hexnib(hex[i * 2 + 1]));
}

/* RFC 8032 5.1.3 step 1: "If the resulting value is >= p, decoding fails."
 * y = p itself (p = 2^255-19), little-endian, x_0 = 0 (bit 255 clear). p's
 * low byte is 0xed (2^255-19 mod 256 = 256-19 = 237 = 0xed) and all other
 * bytes 0xff except the top byte 0x7f (bit 255 cleared, bits 254..0 set). */
static void test_ed25519_field_decode_rejects_y_ge_p(void) {
  quic_ed_ge p;
  u8         in[32];
  edf_hexbytes(
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", in,
      32);
  CHECK(quic_ed_ge_decode(&p, in) == 0);
}

/* y = p - 1 (canonical, the largest valid y) must still decode; the
 * canonical-encoding check must not reject legitimate boundary values. */
static void test_ed25519_field_decode_accepts_y_eq_pm1(void) {
  quic_ed_ge p;
  u8         in[32];
  edf_hexbytes(
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", in,
      32);
  CHECK(quic_ed_ge_decode(&p, in) == 1);
}

/* RFC 8032 5.1.3 step 4: "If x = 0, and x_0 = 1, decoding fails." y = 1 gives
 * u = y^2-1 = 0, so x = 0 is the unique square root; x_0 = 1 (bit 255 set)
 * must then be rejected. */
static void test_ed25519_field_decode_rejects_x0_when_x_zero(void) {
  quic_ed_ge p;
  u8         in[32];
  edf_hexbytes(
      "0100000000000000000000000000000000000000000000000000000000000080", in,
      32);
  CHECK(quic_ed_ge_decode(&p, in) == 0);
}

/* The same x = 0 point with x_0 = 0 (the correct sign bit) must decode. */
static void test_ed25519_field_decode_accepts_x_zero_x0_zero(void) {
  quic_ed_ge p;
  u8         in[32];
  edf_hexbytes(
      "0100000000000000000000000000000000000000000000000000000000000000", in,
      32);
  CHECK(quic_ed_ge_decode(&p, in) == 1);
}

/* RFC 8032 5.1.3 step 3 case 3: "no square root exists for modulo p, and
 * decoding fails." y = 2 makes u/v a quadratic non-residue mod p (hand
 * re-derived: legendre((y^2-1) * inv(d*y^2+1)) == -1 for y = 2), so no x
 * satisfies the curve equation for this y. */
static void test_ed25519_field_decode_rejects_no_sqrt(void) {
  quic_ed_ge p;
  u8         in[32];
  edf_hexbytes(
      "0200000000000000000000000000000000000000000000000000000000000000", in,
      32);
  CHECK(quic_ed_ge_decode(&p, in) == 0);
}

/* Regression for the fe_tobytes carry bug this suite's Red run exposed: a
 * field element whose raw (pre-reduction) limbs sum to exactly p must
 * reduce to 0, not to 19. y = 1 drives decode_uv's u = y^2-1 through exactly
 * that pre-reduction value, so a correct decode of y=1,x_0=0 (checked above)
 * is itself evidence the carry chain is now correct; this test pins the
 * known-good RFC 8032 7.1 TEST 1 public key still round-trips through
 * decode/encode, which depends on fe_tobytes across many field elements. */
static void test_ed25519_field_decode_encode_roundtrip(void) {
  quic_ed_ge p;
  u8         in[32], out[32];
  edf_hexbytes(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", in,
      32);
  CHECK(quic_ed_ge_decode(&p, in) == 1);
  quic_ed_ge_encode(out, &p);
  for (usz i = 0; i < 32; i++) CHECK(out[i] == in[i]);
}

void test_ed25519_field(void) {
  test_ed25519_field_decode_rejects_y_ge_p();
  test_ed25519_field_decode_accepts_y_eq_pm1();
  test_ed25519_field_decode_rejects_x0_when_x_zero();
  test_ed25519_field_decode_accepts_x_zero_x0_zero();
  test_ed25519_field_decode_rejects_no_sqrt();
  test_ed25519_field_decode_encode_roundtrip();
}
