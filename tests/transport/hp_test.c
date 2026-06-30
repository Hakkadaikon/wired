#include "test.h"

static void uhx(const char *hex, u8 *out, usz n) {
  for (usz i = 0; i < n; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

/* RFC 9001 5.4.2: client hp key, sample, and resulting mask. */
static void test_hp_mask(void) {
  u8          hpkey[16], sample[16], mask[5];
  quic_aes128 a;
  uhx("9f50449e04a0e810283a1e9933adedd2", hpkey, 16);
  uhx("d1b1c98dd7689fb8ec11d242b123dc9b", sample, 16);
  quic_aes128_init(&a, hpkey);
  quic_hp_mask(&a, sample, mask);
  u8 want[5];
  uhx("437b9aec36", want, 5);
  for (usz i = 0; i < 5; i++) CHECK(mask[i] == want[i]);
}

/* Applying the mask twice restores the original (XOR is self-inverse). */
static void test_hp_apply_roundtrip(void) {
  u8 mask[5] = {0x43, 0x7b, 0x9a, 0xec, 0x36};
  u8 byte0 = 0xc3, pn[4] = {0x00, 0x00, 0x00, 0x02};
  u8 b0_orig = byte0, pn_orig[4] = {0x00, 0x00, 0x00, 0x02};
  quic_hp_apply(mask, &byte0, pn, 4, QUIC_HP_LONG_MASK);
  CHECK(byte0 != b0_orig); /* protection changed the low bits */
  quic_hp_apply(mask, &byte0, pn, 4, QUIC_HP_LONG_MASK);
  CHECK(byte0 == b0_orig);
  for (usz i = 0; i < 4; i++) CHECK(pn[i] == pn_orig[i]);
}

void test_hp(void) {
  test_hp_mask();
  test_hp_apply_roundtrip();
}
