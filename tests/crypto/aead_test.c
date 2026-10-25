#include "test.h"

/* uh2 parses hex into out; returns byte count. */
static usz uh2(const char* hex, u8* out) {
  usz i = 0;
  while (hex[i * 2] != 0) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    i++;
  }
  return i;
}

/* RFC 8439 2.8.2 worked example. */
static void test_chapoly_rfc(void) {
  u8 key[32], nonce[12], aad[12], pt[114], ct[114 + 16];
  u8 want_ct[114], want_tag[16];
  uh2("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key);
  uh2("070000004041424344454647", nonce);
  usz al = uh2("50515253c0c1c2c3c4c5c6c7", aad);
  usz n =
      uh2("4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
          "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
          "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
          "637265656e20776f756c642062652069742e",
          pt);
  uh2("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
      "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
      "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
      "3ff4def08e4b7a9de576d26586cec64b6116",
      want_ct);
  uh2("1ae10b594f09e26a7e902ecbd0600691", want_tag);

  chapoly_ctx c = {key, nonce, {aad, al}};
  chapoly_seal(&c, wired_span_of(pt, n), ct);
  for (usz i = 0; i < n; i++) {
    CHECK(ct[i] == want_ct[i]);
  }
  for (usz i = 0; i < 16; i++) {
    CHECK(ct[n + i] == want_tag[i]);
  }
}

static void test_chapoly_open(void) {
  u8 key[32] = {0}, nonce[12] = {0};
  u8 pt[20], ct[36], dec[20], bad[36]; /* ct = ciphertext || tag */
  for (usz i = 0; i < 20; i++) {
    pt[i]  = (u8)(i * 7);
    dec[i] = 0xCC;
  }
  chapoly_ctx c = {key, nonce, {(const u8*)"aad", 3}};
  chapoly_seal(&c, wired_span_of(pt, 20), ct);
  CHECK(chapoly_open(&c, wired_span_of(ct, 36), dec));
  for (usz i = 0; i < 20; i++) {
    CHECK(dec[i] == pt[i]);
  }
  /* tamper the tag: reject, leave dec untouched */
  for (usz i = 0; i < 20; i++) {
    dec[i] = 0xCC;
  }
  for (usz i = 0; i < 36; i++) {
    bad[i] = ct[i];
  }
  bad[20 + 7] ^= 0x80;
  CHECK(chapoly_open(&c, wired_span_of(bad, 36), dec) == 0);
  for (usz i = 0; i < 20; i++) {
    CHECK(dec[i] == 0xCC);
  }
}

/* Pinning: chapoly_open must reject a tampered tag and never write plaintext
 * on rejection (V-0420/V-0769). */
static void test_aead_tamper_rejects(void) {
  u8 key[32] = {0}, nonce[12] = {0};
  u8 pt[16], ct[32], dec[16];
  for (usz i = 0; i < 16; i++) {
    pt[i]  = (u8)(i * 5);
    dec[i] = 0xBB;
  }
  chapoly_ctx c = {key, nonce, {(const u8*)"a", 1}};
  chapoly_seal(&c, wired_span_of(pt, 16), ct);
  ct[31] ^= 0x01;
  CHECK(chapoly_open(&c, wired_span_of(ct, 32), dec) == 0);
  for (usz i = 0; i < 16; i++) {
    CHECK(dec[i] == 0xBB);
  }
}

/* RFC 8439 A.3 #2/#3 text ("Any submission to the IETF intended ...", 375
 * bytes), shared by both vectors. */
#define RFC8439_A3_IETF_TEXT                                         \
  "416e79207375626d697373696f6e20746f20746865204945544620696e74656e" \
  "6465642062792074686520436f6e7472696275746f7220666f72207075626c69" \
  "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446" \
  "20496e7465726e65742d4472616674206f722052464320616e6420616e792073" \
  "746174656d656e74206d6164652077697468696e2074686520636f6e74657874" \
  "206f6620616e204945544620616374697669747920697320636f6e7369646572" \
  "656420616e20224945544620436f6e747269627574696f6e222e205375636820" \
  "73746174656d656e747320696e636c756465206f72616c2073746174656d656e" \
  "747320696e20494554462073657373696f6e732c2061732077656c6c20617320" \
  "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361" \
  "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c" \
  "207768696368206172652061646472657373656420746f"

/* RFC 8439 A.3 Poly1305 vectors #1-#11: one-time key, text, tag. Hex
 * extracted from the RFC text and re-checked against an independent Python
 * big-integer Poly1305 before being baked in. */
static const struct {
  const char* key;
  const char* msg;
  const char* tag;
} rfc8439_a3_vecs[] = {
    {"0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000"
     "0000000000000000000000000000000000000000000000000000000000000000",
     "00000000000000000000000000000000"},
    {"0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
     RFC8439_A3_IETF_TEXT, "36e5f6b5c5e06070f0efca96227a863e"},
    {"36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
     RFC8439_A3_IETF_TEXT, "f3477e7cd95417af89a6b8794c310cf0"},
    {"1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
     "2754776173206272696c6c69672c20616e642074686520736c6974687920746f"
     "7665730a446964206779726520616e642067696d626c6520696e207468652077"
     "6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665"
     "732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
     "4541669a7eaaee61e708dc7cbcc5eb62"},
    {"0200000000000000000000000000000000000000000000000000000000000000",
     "ffffffffffffffffffffffffffffffff", "03000000000000000000000000000000"},
    {"02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
     "02000000000000000000000000000000", "03000000000000000000000000000000"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff"
     "11000000000000000000000000000000",
     "05000000000000000000000000000000"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe"
     "01010101010101010101010101010101",
     "00000000000000000000000000000000"},
    {"0200000000000000000000000000000000000000000000000000000000000000",
     "fdffffffffffffffffffffffffffffff", "faffffffffffffffffffffffffffffff"},
    {"0100000000000000040000000000000000000000000000000000000000000000",
     "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
     "0000000000000000000000000000000001000000000000000000000000000000",
     "14000000000000005500000000000000"},
    {"0100000000000000040000000000000000000000000000000000000000000000",
     "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
     "00000000000000000000000000000000",
     "13000000000000000000000000000000"},
};

/* RFC 8439 A.4 Poly1305 key generation #1-#3: key, nonce, one-time key. */
static const struct {
  const char* key;
  const char* nonce;
  const char* otk;
} rfc8439_a4_vecs[] = {
    {"0000000000000000000000000000000000000000000000000000000000000000",
     "000000000000000000000000",
     "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"},
    {"0000000000000000000000000000000000000000000000000000000000000001",
     "000000000000000000000002",
     "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739"},
    {"1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
     "000000000000000000000002",
     "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae"},
};

/* RFC 8439 A.5: key, nonce, AAD, ciphertext || received tag, and the
 * plaintext (decrypted by an independent Python ChaCha20; it starts
 * "Internet-Drafts are draft documents"). */
static const char* const rfc8439_a5_key =
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
static const char* const rfc8439_a5_nonce = "000000000102030405060708";
static const char* const rfc8439_a5_aad   = "f33388860000000000004e91";
static const char* const rfc8439_a5_ct_tag =
    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
    "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
    "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
    "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
    "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
    "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
    "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
    "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
    "a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38";
static const char* const rfc8439_a5_pt =
    "496e7465726e65742d4472616674732061726520647261667420646f63756d65"
    "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
    "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
    "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
    "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
    "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
    "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
    "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
    "726573732e2fe2809d";

/* Compare n bytes. */
static int rfc8439_eq(const u8* a, const u8* b, usz n) {
  u8 d = 0;
  for (usz i = 0; i < n; i++) {
    d |= (u8)(a[i] ^ b[i]);
  }
  return d == 0;
}

static int rfc8439_a3_one(usz i) {
  u8  key[32], msg[375], want[16], tag[16];
  usz n;
  uh2(rfc8439_a3_vecs[i].key, key);
  n = uh2(rfc8439_a3_vecs[i].msg, msg);
  uh2(rfc8439_a3_vecs[i].tag, want);
  poly1305(key, msg, n, tag);
  return rfc8439_eq(tag, want, 16);
}

/* RFC 8439 A.3 #1-#11, including r = 0 (#2), the partially reduced final
 * value (#5), s-addition overflow (#6), 2^130-5 itself (#8) and the
 * 131-bit 5*H+L intermediates (#10, #11). */
static void test_rfc8439_a3_poly1305(void) {
  for (usz i = 0; i < sizeof(rfc8439_a3_vecs) / sizeof(rfc8439_a3_vecs[0]);
       i++) {
    CHECK(rfc8439_a3_one(i));
  }
}

/* RFC 8439 A.4 #1-#3: the one-time key is the first 32 bytes of the
 * counter-0 block (2.6), which chapoly's tag derivation uses. */
static void test_rfc8439_a4_keygen(void) {
  for (usz i = 0; i < 3; i++) {
    u8 key[32], nonce[12], want[32], block[64];
    uh2(rfc8439_a4_vecs[i].key, key);
    uh2(rfc8439_a4_vecs[i].nonce, nonce);
    uh2(rfc8439_a4_vecs[i].otk, want);
    chacha20_block(key, 0, nonce, block);
    CHECK(rfc8439_eq(block, want, 32));
  }
}

/* RFC 8439 A.5: the received ciphertext authenticates and decrypts to the
 * expected plaintext; a flipped tag bit is rejected. */
static void test_rfc8439_a5_open(void) {
  u8  key[32], nonce[12], aad[12], ct[265 + 16], want[265], pt[265];
  usz al, n;
  uh2(rfc8439_a5_key, key);
  uh2(rfc8439_a5_nonce, nonce);
  al = uh2(rfc8439_a5_aad, aad);
  n  = uh2(rfc8439_a5_ct_tag, ct);
  uh2(rfc8439_a5_pt, want);
  chapoly_ctx c = {key, nonce, {aad, al}};
  CHECK(n == sizeof(ct));
  CHECK(chapoly_open(&c, wired_span_of(ct, n), pt) == 1);
  CHECK(rfc8439_eq(pt, want, sizeof(want)));
  ct[n - 1] ^= 0x01;
  CHECK(chapoly_open(&c, wired_span_of(ct, n), pt) == 0);
}

void test_aead(void) {
  test_chapoly_rfc();
  test_chapoly_open();
  test_aead_tamper_rejects();
  test_rfc8439_a3_poly1305();
  test_rfc8439_a4_keygen();
  test_rfc8439_a5_open();
}
