#include "test.h"

/* RFC 9001 A.2 nonce construction: client_iv fa044b2f42a3fd3b46fb255c with
 * packet number 2 XORed into the low bytes gives ...255c ^ 02 = ...255e. */
static void test_protect_nonce_rfc(void) {
  u8 iv[12] = {0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3,
               0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c};
  u8 nonce[12];
  protect_nonce(iv, 2, nonce);
  u8 want[12] = {0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3,
                 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5e};
  for (usz i = 0; i < 12; i++) {
    CHECK(nonce[i] == want[i]);
  }
  /* higher pn bytes land in the upper part of the low-8 region */
  protect_nonce(iv, 0x0102, nonce);
  CHECK(nonce[11] == (0x5c ^ 0x02) && nonce[10] == (0x25 ^ 0x01));
}

/* Seal then open returns the original header and payload (protect∘unprotect
 * = id), using keys derived exactly as for a real Initial packet. */
static void test_protect_roundtrip(void) {
  const u8     dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  initial_keys keys;
  aes128       hp;
  initial_derive(wired_span_of(dcid, 8), 0, VERSION_1, &keys);
  aes128_init(&hp, keys.hp);

  /* a long-header Initial with a 4-byte packet number at offset 18 */
  u8 hdr[18] = {
      0xc3, 0,    0,    0,    1, 8, 0x83, 0x94, 0xc8, 0xf0,
      0x3e, 0x51, 0x57, 0x08, 0, 0, 0,    0}; /* scid len 0, token len 0, then
                                                 pn placeholder */
  /* place the 4-byte pn (=2) at the end of the header */
  hdr[14]            = 0;
  hdr[15]            = 0;
  hdr[16]            = 0;
  hdr[17]            = 2;
  const u8 payload[] = {0x06, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};

  u8              pkt[64];
  protect_keys    k   = {&keys, &hp};
  protect_seal_io sio = {
      wired_span_of(hdr, 18),
      14,
      4,
      2,
      wired_span_of(payload, sizeof(payload)),
      wired_mspan_of(pkt, sizeof(pkt))};
  usz total = protect_seal(&k, &sio);
  CHECK(total == 18 + sizeof(payload) + 16);
  /* header protection altered byte0's low bits and the packet number */
  CHECK(pkt[0] != 0xc3 || pkt[17] != 2);

  protect_open_io oio = {wired_mspan_of(pkt, total), 18, 14, 4, 2};
  usz             pl  = protect_open(&k, &oio);
  CHECK(pl == sizeof(payload));
  CHECK(pkt[0] == 0xc3 && pkt[17] == 2); /* header restored */
  for (usz i = 0; i < sizeof(payload); i++) {
    CHECK(pkt[18 + i] == payload[i]); /* payload restored */
  }
}

/* A tampered ciphertext byte makes open fail. */
static void test_protect_tamper(void) {
  const u8     dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  initial_keys keys;
  aes128       hp;
  initial_derive(wired_span_of(dcid, 8), 0, VERSION_1, &keys);
  aes128_init(&hp, keys.hp);
  u8       hdr[18] = {0xc3, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 2};
  const u8 payload[] = {1, 2, 3, 4};
  u8       pkt[64];
  protect_keys    k   = {&keys, &hp};
  protect_seal_io sio = {
      wired_span_of(hdr, 18),
      14,
      4,
      2,
      wired_span_of(payload, sizeof(payload)),
      wired_mspan_of(pkt, sizeof(pkt))};
  usz total = protect_seal(&k, &sio);
  pkt[20] ^= 0x40; /* flip a ciphertext bit */
  protect_open_io oio = {wired_mspan_of(pkt, total), 18, 14, 4, 2};
  CHECK(protect_open(&k, &oio) == 0);
}

/* RFC 9001 5.3: sealing needs header + payload + 16-byte tag of room; one
 * byte short fails for both seal paths, as does a suite with no AEAD. */
static void test_protect_seal_rejects_short_out_and_bad_suite(void) {
  const u8     dcid[8]    = {1, 2, 3, 4, 5, 6, 7, 8};
  const u8     hdr[18]    = {0xc3, 0, 0, 0, 1};
  const u8     payload[4] = {1, 2, 3, 4};
  u8           pkt[64];
  initial_keys keys;
  aes128       hp;
  initial_derive(wired_span_of(dcid, 8), 0, VERSION_1, &keys);
  aes128_init(&hp, keys.hp);
  protect_keys    k   = {&keys, &hp};
  protect_seal_io sio = {
      wired_span_of(hdr, 18),
      14,
      4,
      2,
      wired_span_of(payload, 4),
      wired_mspan_of(pkt, 18 + 4 + 16 - 1)};
  CHECK(protect_seal(&k, &sio) == 0);
  CHECK(protect_seal_suite(TLS_AES_128_GCM_SHA256, &k, &sio) == 0);
  sio.out = wired_mspan_of(pkt, sizeof(pkt));
  CHECK(protect_seal_suite(TLS_AES_128_GCM_SHA256, &k, &sio) == 18 + 4 + 16);
  CHECK(protect_seal_suite(0x1304, &k, &sio) == 0); /* TLS_AES_128_CCM */
}

void test_protect(void) {
  test_protect_seal_rejects_short_out_and_bad_suite();
  test_protect_nonce_rfc();
  test_protect_roundtrip();
  test_protect_tamper();
}
