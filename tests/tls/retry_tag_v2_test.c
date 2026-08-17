#include "crypto/symmetric/aead/gcm/gcm.h"
#include "test.h"

/* RFC 9369 3.3.3 v2 key/nonce golden values, and they differ from the
 * RFC 9001 5.8 v1 key/nonce. */
static void test_retry_tag_v2_constants(void) {
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

/* RFC 9369 Appendix A.4: the full sample v2 Retry packet, integrity tag
 * included:
 *   cf6b3343cf0008f067a5502a4262b574 6f6b656ec8646ce8bfe33952d9555436
 *   65dcc7b6
 * keyed off the client-chosen ODCID 0x8394c8f03e515708 from Appendix A
 * (same ODCID as the v1 A.4 vector in retry_tag_test.c). Byte layout: byte0
 * 0xcf (long header, type bits 00 = Retry per RFC 9369 3.2), Version
 * 6b3343cf, DCID Len 00, SCID Len 08, SCID f067a5502a4262b5, Token "token"
 * (5 bytes), then the 16-byte tag c8646ce8bfe33952d955543665dcc7b6. The tag
 * is AEAD_AES_128_GCM sealed (empty plaintext) over the Retry Pseudo-Packet
 * (RFC 9001 5.8: ODCID Len + ODCID + the Retry bytes above the tag) under
 * the RFC 9369 3.3.3 v2 key/nonce -- reproduced here via the same GCM
 * primitive quic_retry_tag.c uses for v1, since quic_retry_tag itself is
 * hardwired to the v1 constants (see retry_tag.c). */
static void test_retry_tag_v2_rfc9369_a4_vector(void) {
  const u8 odcid[8]       = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  const u8 retry_no_tag[] = {0xcf, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08,
                             0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
                             0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e};
  const u8 want_tag[16]   = {0xc8, 0x64, 0x6c, 0xe8, 0xbf, 0xe3, 0x39, 0x52,
                             0xd9, 0x55, 0x54, 0x36, 0x65, 0xdc, 0xc7, 0xb6};

  const u8* key;
  const u8* nonce;
  usz       klen, nlen;
  quic_retry_tag_v2_key(&key, &klen);
  quic_retry_tag_v2_nonce(&nonce, &nlen);

  u8  aad[1 + 8 + sizeof(retry_no_tag)];
  usz n    = 0;
  aad[n++] = (u8)sizeof(odcid);
  for (usz i = 0; i < sizeof(odcid); i++) aad[n++] = odcid[i];
  for (usz i = 0; i < sizeof(retry_no_tag); i++) aad[n++] = retry_no_tag[i];

  quic_aes128 a;
  u8          tag[16];
  quic_aes128_init(&a, key);
  quic_gcm_ctx g = {&a, nonce, wired_span_of(aad, n)};
  quic_gcm_seal(&g, wired_span_of(0, 0), tag);

  for (usz i = 0; i < 16; i++) CHECK(tag[i] == want_tag[i]);
}

void test_retry_tag_v2(void) {
  test_retry_tag_v2_constants();
  test_retry_tag_v2_rfc9369_a4_vector();
}
