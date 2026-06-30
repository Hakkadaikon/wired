#include "test.h"

/* Build a short-header packet [byte0, pn(pn_len), payload] in buf and seal it,
 * then open it back; checks that the payload round-trips for the given suite.
 */
static void pcs_roundtrip(u16 suite, const u8 *key, usz keylen, u8 byte0) {
  u8 iv[12], hp[32];
  for (usz i = 0; i < 12; i++) iv[i] = (u8)(0x10 + i);
  for (usz i = 0; i < keylen; i++) hp[i] = (u8)(0x80 + i);

  /* byte0 + 4-byte pn at offset 1, then a short payload. HP samples 16 bytes
   * at pn_off+4, so the buffer must be long enough past the pn region. */
  u8 pkt[64];
  pkt[0]             = byte0;
  pkt[1]             = 0;
  pkt[2]             = 0;
  pkt[3]             = 0;
  pkt[4]             = 7; /* pn = 7, pn_len = 4 */
  const u8 payload[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14};
  for (usz i = 0; i < sizeof(payload); i++) pkt[5 + i] = payload[i];

  usz out_len = 0;
  CHECK(
      quic_protectcs_seal(
          suite, key, iv, hp, 7, pkt, 1, 4, sizeof(payload), &out_len) == 1);
  CHECK(out_len == 5 + sizeof(payload) + 16);
  /* HP must have altered byte0 and/or the packet number. */
  CHECK(pkt[0] != byte0 || pkt[4] != 7);

  const u8 *got     = 0;
  usz       got_len = 0;
  CHECK(
      quic_protectcs_open(
          suite, key, iv, hp, pkt, out_len, 1, &got, &got_len) == 1);
  CHECK(got_len == sizeof(payload));
  for (usz i = 0; i < sizeof(payload); i++) CHECK(got[i] == payload[i]);
}

/* Seal the same plaintext under both suites and confirm the protected header
 * bytes differ (per-suite HP mask) and tampering is rejected. */
static void cross_suite(void) {
  u8 key[32], iv[12], hp[32];
  for (usz i = 0; i < 32; i++) key[i] = (u8)(0x40 + i);
  for (usz i = 0; i < 12; i++) iv[i] = (u8)(0x10 + i);
  for (usz i = 0; i < 32; i++) hp[i] = (u8)(0x80 + i);

  u8 a[64], c[64];
  for (usz s = 0; s < 64; s++) {
    a[s] = (u8)s;
    c[s] = (u8)s;
  }
  a[0] = 0x43;
  c[0] = 0x43; /* short header, low 2 bits => pn_len 4 */
  a[4] = 9;
  c[4] = 9; /* pn = 9 in the low pn byte */

  usz la = 0, lc = 0;
  CHECK(
      quic_protectcs_seal(
          QUIC_TLS_AES_128_GCM_SHA256, key, iv, hp, 9, a, 1, 4, 20, &la) == 1);
  CHECK(
      quic_protectcs_seal(
          QUIC_TLS_CHACHA20_POLY1305_SHA256, key, iv, hp, 9, c, 1, 4, 20,
          &lc) == 1);
  /* Different HP construction -> protected byte0/pn region differs. */
  int diff = (a[0] != c[0]);
  for (usz i = 1; i <= 4; i++) diff |= (a[i] != c[i]);
  CHECK(diff);

  /* Tampering the ChaCha ciphertext tag fails authentication. */
  c[lc - 1] ^= 0xff;
  const u8 *p  = 0;
  usz       pl = 0;
  CHECK(
      quic_protectcs_open(
          QUIC_TLS_CHACHA20_POLY1305_SHA256, key, iv, hp, c, lc, 1, &p, &pl) ==
      0);
}

void test_protectcs(void) {
  u8 aes_key[16], cha_key[32];
  for (usz i = 0; i < 16; i++) aes_key[i] = (u8)(0x30 + i);
  for (usz i = 0; i < 32; i++) cha_key[i] = (u8)(0x50 + i);

  /* RFC 9001 5.3/5.4: full seal/open round-trip per suite. */
  /* byte0 low 2 bits encode pn_len-1, so 0x43 / 0xc3 mean pn_len = 4. */
  pcs_roundtrip(QUIC_TLS_AES_128_GCM_SHA256, aes_key, 16, 0x43);
  pcs_roundtrip(QUIC_TLS_CHACHA20_POLY1305_SHA256, cha_key, 32, 0x43);
  /* long-header form bit (0xc3) exercises the 4-low-bit mask path. */
  pcs_roundtrip(QUIC_TLS_CHACHA20_POLY1305_SHA256, cha_key, 32, 0xc3);

  cross_suite();

  /* Unknown suite seals/opens nothing. */
  u8 pkt[64];
  for (usz i = 0; i < 64; i++) pkt[i] = (u8)i;
  usz n = 1;
  CHECK(
      quic_protectcs_seal(
          0x0000, cha_key, cha_key, cha_key, 1, pkt, 1, 4, 20, &n) == 0);
  const u8 *p  = 0;
  usz       pl = 0;
  CHECK(
      quic_protectcs_open(
          0x0000, cha_key, cha_key, cha_key, pkt, 41, 1, &p, &pl) == 0);
}
