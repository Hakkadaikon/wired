#include "test.h"

/* RFC 9369 3.3.3 v2 key/nonce golden values, and they differ from the
 * RFC 9001 5.8 v1 key/nonce. */
void test_retry_tag_v2(void) {
  static const u8 want_key[16]   = {0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac,
                                    0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce,
                                    0xad, 0x7c, 0xcc, 0x92};
  static const u8 want_nonce[12] = {0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c,
                                    0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a};
  static const u8 v1_key[16] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
                                0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e};
  static const u8 v1_nonce[12] = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
                                  0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};

  const u8 *key, *nonce;
  usz       klen, nlen;

  quic_retry_tag_v2_key(&key, &klen);
  quic_retry_tag_v2_nonce(&nonce, &nlen);

  CHECK(klen == 16);
  CHECK(nlen == 12);

  int key_match = 1, nonce_match = 1, key_diff = 0, nonce_diff = 0;
  for (usz i = 0; i < 16; i++) {
    if (key[i] != want_key[i]) key_match = 0;
    if (key[i] != v1_key[i]) key_diff = 1;
  }
  for (usz i = 0; i < 12; i++) {
    if (nonce[i] != want_nonce[i]) nonce_match = 0;
    if (nonce[i] != v1_nonce[i]) nonce_diff = 1;
  }
  CHECK(key_match == 1);   /* golden v2 key */
  CHECK(nonce_match == 1); /* golden v2 nonce */
  CHECK(key_diff == 1);    /* differs from v1 key */
  CHECK(nonce_diff == 1);  /* differs from v1 nonce */
}
