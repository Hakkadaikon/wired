#include "crypto/kdf/hkdf/hkdf.h"
#include "crypto/symmetric/aead/chacha/aead.h"
#include "test.h"
#include "transport/packet/protect/hp/hp_chacha.h"
#include "transport/version/version/version.h"

/* RFC 9369 Appendix A.5: "ChaCha20-Poly1305 Short Header Packet" -- the
 * application write secret is expanded (RFC 9369 3.3.2 "quicv2 " labels)
 * into key/iv/hp/ku, then those protect a minimal 1-byte-PING short-header
 * packet. This reproduces every value in the appendix, including the
 * "quicv2 ku" key-update secret (RFC 9369 3.3.2, closed by
 * quic_ku_next_secret_v -- see kuderive.c). */

static const u8 A5_SECRET[32] = {
    0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42,
    0x27, 0x48, 0xad, 0x00, 0xa1, 0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0,
    0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b};

static const u8 A5_KEY[32] = {0x3b, 0xfc, 0xdd, 0xd7, 0x2b, 0xcf, 0x02, 0x54,
                              0x1d, 0x7f, 0xa0, 0xdd, 0x1f, 0x5f, 0x9e, 0xee,
                              0xa8, 0x17, 0xe0, 0x9a, 0x69, 0x63, 0xa0, 0xe6,
                              0xc7, 0xdf, 0x0f, 0x9a, 0x1b, 0xab, 0x90, 0xf2};

static const u8 A5_IV[12] = {0xa6, 0xb5, 0xbc, 0x6a, 0xb7, 0xda,
                             0xfc, 0xe3, 0x0f, 0xff, 0xf5, 0xdd};

static const u8 A5_HP[32] = {0xd6, 0x59, 0x76, 0x0d, 0x2b, 0xa4, 0x34, 0xa2,
                             0x26, 0xfd, 0x37, 0xb3, 0x5c, 0x69, 0xe2, 0xda,
                             0x82, 0x11, 0xd1, 0x0c, 0x4f, 0x12, 0x53, 0x87,
                             0x87, 0xd6, 0x56, 0x45, 0xd5, 0xd1, 0xb8, 0xe2};

static const u8 A5_KU[32] = {0xc6, 0x93, 0x74, 0xc4, 0x9e, 0x3d, 0x2a, 0x94,
                             0x66, 0xfa, 0x68, 0x9e, 0x49, 0xd4, 0x76, 0xdb,
                             0x5d, 0x0d, 0xfb, 0xc8, 0x7d, 0x32, 0xce, 0xea,
                             0xa6, 0x34, 0x3f, 0xd0, 0xae, 0x4c, 0x7d, 0x88};

/* RFC 9369 3.3.2 "quicv2 key"/"quicv2 iv"/"quicv2 hp" expand from the write
 * secret to exactly the appendix's key/iv/hp. */
static void test_v2ku_appendix_key_iv_hp(void) {
  u8         key[32], iv[12], hp[32];
  hkdf_label lk = {"quicv2 key", 10, {0, 0}};
  hkdf_label li = {"quicv2 iv", 9, {0, 0}};
  hkdf_label lh = {"quicv2 hp", 9, {0, 0}};
  hkdf_expand_label(A5_SECRET, &lk, wired_mspan_of(key, 32));
  hkdf_expand_label(A5_SECRET, &li, wired_mspan_of(iv, 12));
  hkdf_expand_label(A5_SECRET, &lh, wired_mspan_of(hp, 32));
  for (usz i = 0; i < 32; i++) CHECK(key[i] == A5_KEY[i]);
  for (usz i = 0; i < 12; i++) CHECK(iv[i] == A5_IV[i]);
  for (usz i = 0; i < 32; i++) CHECK(hp[i] == A5_HP[i]);
}

/* RFC 9369 3.3.2 "quicv2 ku": the key-update secret the appendix derives
 * (unused further in its own example) matches quic_ku_next_secret_v under
 * QUIC_VERSION_2 -- the E-13 fix this vector depends on. */
static void test_v2ku_appendix_ku(void) {
  u8 ku[32];
  quic_ku_next_secret_v(QUIC_VERSION_2, A5_SECRET, ku);
  for (usz i = 0; i < 32; i++) CHECK(ku[i] == A5_KU[i]);
}

/* RFC 9369 3.3.2 (referencing RFC 9001 5.3): nonce = iv XOR left-padded
 * packet number (654360564), matching the appendix's nonce exactly. */
static void test_v2ku_appendix_nonce(void) {
  const u64 pn             = 654360564u;
  const u8  want_nonce[12] = {0xa6, 0xb5, 0xbc, 0x6a, 0xb7, 0xda,
                              0xfc, 0xe3, 0x28, 0xff, 0x4a, 0x29};
  u8        pn_be[12]      = {0};
  u8        nonce[12];
  for (usz i = 0; i < 8; i++) pn_be[11 - i] = (u8)(pn >> (8 * i));
  for (usz i = 0; i < 12; i++) nonce[i] = A5_IV[i] ^ pn_be[i];
  for (usz i = 0; i < 12; i++) CHECK(nonce[i] == want_nonce[i]);
}

/* RFC 9369 A.5: sealing the 1-byte PING payload (0x01) under (key, nonce,
 * aad=unprotected header 4200bff4) produces the appendix's payload
 * ciphertext exactly. */
static void test_v2ku_appendix_seal(void) {
  const u8 nonce[12]   = {0xa6, 0xb5, 0xbc, 0x6a, 0xb7, 0xda,
                          0xfc, 0xe3, 0x28, 0xff, 0x4a, 0x29};
  const u8 aad[4]      = {0x42, 0x00, 0xbf, 0xf4};
  const u8 pt[1]       = {0x01};
  const u8 want_ct[17] = {0x0a, 0xe7, 0xb6, 0xb9, 0x32, 0xbc, 0x27, 0xd7, 0x86,
                          0xf4, 0xbc, 0x2b, 0xb2, 0x0f, 0x21, 0x62, 0xba};
  u8       ct[17];
  chapoly_ctx c = {A5_KEY, nonce, wired_span_of(aad, 4)};
  chapoly_seal(&c, wired_span_of(pt, 1), ct);
  for (usz i = 0; i < 17; i++) CHECK(ct[i] == want_ct[i]);
}

/* RFC 9369 A.5: the ChaCha20 header-protection mask over the appendix's
 * 16-byte sample (RFC 9001 5.4.4 counter/nonce split), then XORed onto the
 * unprotected header, reproduces the appendix's protected header exactly. */
static void test_v2ku_appendix_header_protection(void) {
  const u8 sample[16]     = {0xe7, 0xb6, 0xb9, 0x32, 0xbc, 0x27, 0xd7, 0x86,
                             0xf4, 0xbc, 0x2b, 0xb2, 0x0f, 0x21, 0x62, 0xba};
  const u8 want_mask[5]   = {0x97, 0x58, 0x0e, 0x32, 0xbf};
  const u8 want_header[4] = {0x55, 0x58, 0xb1, 0xc6};
  u8       mask[5];
  u8       header[4] = {0x42, 0x00, 0xbf, 0xf4};
  quic_hp_chacha_mask(A5_HP, sample, mask);
  for (usz i = 0; i < 5; i++) CHECK(mask[i] == want_mask[i]);
  /* RFC 9001 5.4.1: short header masks the low 5 bits of byte0. */
  header[0] ^= mask[0] & 0x1f;
  for (usz i = 1; i < 4; i++) header[i] ^= mask[i];
  for (usz i = 0; i < 4; i++) CHECK(header[i] == want_header[i]);
}

void test_v2ku_appendix(void) {
  test_v2ku_appendix_key_iv_hp();
  test_v2ku_appendix_ku();
  test_v2ku_appendix_nonce();
  test_v2ku_appendix_seal();
  test_v2ku_appendix_header_protection();
}
