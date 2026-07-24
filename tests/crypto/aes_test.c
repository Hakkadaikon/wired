#include "test.h"

/* hb parses a 32-char hex string into 16 bytes. */
static void hb(const char* hex, u8 out[16]) {
  for (usz i = 0; i < 16; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

/* FIPS 197 Appendix B / C.1 known-answer test. */
static void test_aes_fips197(void) {
  u8          key[16], in[16], out[16], want[16];
  quic_aes128 a;
  hb("2b7e151628aed2a6abf7158809cf4f3c", key);
  hb("3243f6a8885a308d313198a2e0370734", in);
  hb("3925841d02dc09fbdc118597196a0b32", want);
  quic_aes128_init(&a, key);
  quic_aes128_encrypt(&a, in, out);
  for (usz i = 0; i < 16; i++) CHECK(out[i] == want[i]);
}

/* FIPS 197 Appendix C.1: all-from-the-spec vector. */
static void test_aes_appendix_c(void) {
  u8          key[16], in[16], out[16], want[16];
  quic_aes128 a;
  hb("000102030405060708090a0b0c0d0e0f", key);
  hb("00112233445566778899aabbccddeeff", in);
  hb("69c4e0d86a7b0430d8cdb78070b4c55a", want);
  quic_aes128_init(&a, key);
  quic_aes128_encrypt(&a, in, out);
  for (usz i = 0; i < 16; i++) CHECK(out[i] == want[i]);
}

/* FIPS 197 Appendix B: MixColumns multiplies each state column by the fixed
 * matrix [[02,03,01,01],[01,02,03,01],[01,01,02,03],[03,01,01,02]] over
 * GF(2^8). These four (input column, output column) pairs are the Round 1
 * MixColumns step of Appendix B, re-derived by hand from the SubBytes and
 * ShiftRows output ("d4bf5d30 e0b452ae b84111f1 1e2798e5", the state after
 * Round 1 AddRoundKey+SubBytes+ShiftRows) via the matrix definition above:
 * out[0] = 02*a0 ^ 03*a1 ^ a2 ^ a3, out[1] = a0 ^ 02*a1 ^ 03*a2 ^ a3,
 * out[2] = a0 ^ a1 ^ 02*a2 ^ 03*a3, out[3] = 03*a0 ^ a1 ^ a2 ^ 02*a3.
 * mix_one (aes.c) is static; this test file is unified into the same
 * translation unit after aes.c in tests/run.c, so it is directly callable. */
/* Run mix_one on one column and check it against the expected output. */
static void check_mix_one(const u8 in[4], const u8 want[4]) {
  u8 col[4];
  for (usz j = 0; j < 4; j++) col[j] = in[j];
  mix_one(col);
  for (usz j = 0; j < 4; j++) CHECK(col[j] == want[j]);
}

static void test_aes_mix_columns_matrix(void) {
  struct {
    u8 in[4];
    u8 want[4];
  } cases[4] = {
      {{0xd4, 0xbf, 0x5d, 0x30}, {0x04, 0x66, 0x81, 0xe5}},
      {{0xe0, 0xb4, 0x52, 0xae}, {0xe0, 0xcb, 0x19, 0x9a}},
      {{0xb8, 0x41, 0x11, 0xf1}, {0x48, 0xf8, 0xd3, 0x7a}},
      {{0x1e, 0x27, 0x98, 0xe5}, {0x28, 0x06, 0x26, 0x4c}},
  };
  for (usz i = 0; i < 4; i++) check_mix_one(cases[i].in, cases[i].want);
}

void test_aes(void) {
  test_aes_fips197();
  test_aes_appendix_c();
  test_aes_mix_columns_matrix();
}
