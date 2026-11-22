#include "test.h"

/* uh parses hex into out; returns byte count. */
static usz uh(const char* hex, u8* out) {
  usz i = 0;
  while (hex[i * 2] != 0) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    i++;
  }
  return i;
}

/* RFC 8439 A.1 test vector 1: all-zero key, nonce, counter 0. */
static void test_chacha_block(void) {
  u8 key[32] = {0}, nonce[12] = {0}, ks[64], want[64];
  chacha20_block(key, 0, nonce, ks);
  uh("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
     "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
     want);
  for (usz i = 0; i < 64; i++) {
    CHECK(ks[i] == want[i]);
  }
}

/* RFC 8439 2.4.2: encrypt the sunscreen plaintext, key 00..1f, nonce
 * 00:00:00:00:00:00:00:4a:00:00:00:00, counter 1. */
static void test_chacha_encrypt(void) {
  u8 key[32], nonce[12], pt[114], want[114], ct[114];
  for (usz i = 0; i < 32; i++) {
    key[i] = (u8)i;
  }
  uh("000000000000004a00000000", nonce);
  usz n =
      uh("4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
         "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
         "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
         "637265656e20776f756c642062652069742e",
         pt);
  uh("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
     "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
     "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
     "5af90bbf74a35be6b40b8eedf2785e42874d",
     want);
  chacha_ctx c = {key, nonce, 1};
  chacha20_xor(&c, wired_span_of(pt, n), ct);
  for (usz i = 0; i < n; i++) {
    CHECK(ct[i] == want[i]);
  }
}

/* RFC 8439 2.1.1: one quarter round (chacha20.c's QR) on a, b, c, d. */
static void test_chacha_quarter_round(void) {
  u32 a = 0x11111111, b = 0x01020304, c = 0x9b8d6f43, d = 0x01234567;
  QR(a, b, c, d);
  CHECK(a == 0xea2a92f4);
  CHECK(b == 0xcb1cf8ce);
  CHECK(c == 0x4581472e);
  CHECK(d == 0x5881c4bb);
}

/* RFC 8439 2.2.1: QUARTERROUND(2, 7, 8, 13) on the sample state changes
 * only words 2, 7, 8 and 13. */
static void test_chacha_quarter_round_state(void) {
  u32       x[16]    = {0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
                        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
                        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
                        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320};
  const u32 want[16] = {0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
                        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
                        0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
                        0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320};
  QR(x[2], x[7], x[8], x[13]);
  for (usz i = 0; i < 16; i++) {
    CHECK(x[i] == want[i]);
  }
}

/* RFC 8439 2.3.2: key 00..1f, nonce 00:00:00:09:00:00:00:4a:00:00:00:00,
 * counter 1 -- the set-up state (init_state), the state after 20 rounds
 * (10 double_round), and the serialized block (chacha20_block). */
static void test_chacha_block_2_3_2(void) {
  static const u32 setup[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                                0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                                0x00000001, 0x09000000, 0x4a000000, 0x00000000};
  static const u32 rounds[16] = {
      0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f, 0xc4f2d0c7, 0xfc62bb2f,
      0x8fa018fc, 0x3f5ec7b7, 0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
      0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2};
  u8  key[32], nonce[12], out[64], want[64];
  u32 s[16];
  for (usz i = 0; i < 32; i++) {
    key[i] = (u8)i;
  }
  uh("000000090000004a00000000", nonce);
  init_state(key, 1, nonce, s);
  for (usz i = 0; i < 16; i++) {
    CHECK(s[i] == setup[i]);
  }
  for (usz i = 0; i < 10; i++) {
    double_round(s);
  }
  for (usz i = 0; i < 16; i++) {
    CHECK(s[i] == rounds[i]);
  }
  uh("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
     "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
     want);
  chacha20_block(key, 1, nonce, out);
  for (usz i = 0; i < 64; i++) {
    CHECK(out[i] == want[i]);
  }
}

/* RFC 8439 2.6.2: the Poly1305 one-time key for key 80..9f, nonce
 * 00:00:00:00:00:01:02:03:04:05:06:07 (aead.c's poly_key). */
static void test_chacha_poly_key_2_6_2(void) {
  u8          key[32], nonce[12], pk[32], want[32];
  chapoly_ctx c = {key, nonce, {0, 0}};
  for (usz i = 0; i < 32; i++) {
    key[i] = (u8)(0x80 + i);
  }
  uh("000000000001020304050607", nonce);
  uh("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646", want);
  poly_key(&c, pk);
  for (usz i = 0; i < 32; i++) {
    CHECK(pk[i] == want[i]);
  }
}

/* RFC 8439 A.1 #2-#5 (key, nonce hex, block counter, keystream hex). */
static const struct {
  const char* key;
  const char* nonce;
  u32         counter;
  const char* ks;
} c8439_a1[4] = {
    {"0000000000000000000000000000000000000000000000000000000000000000",
     "000000000000000000000000", 1,
     "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
     "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"},
    {"0000000000000000000000000000000000000000000000000000000000000001",
     "000000000000000000000000", 1,
     "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a"
     "8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0"},
    {"00ff000000000000000000000000000000000000000000000000000000000000",
     "000000000000000000000000", 2,
     "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca"
     "13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096"},
    {"0000000000000000000000000000000000000000000000000000000000000000",
     "000000000000000000000002", 0,
     "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7"
     "8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d"},
};

/* RFC 8439 A.2 #2-#3 (key, nonce hex, initial counter, plaintext and
 * ciphertext hex). */
static const struct {
  const char* key;
  const char* nonce;
  u32         counter;
  const char* pt;
  const char* ct;
} c8439_a2[2] = {
    {"0000000000000000000000000000000000000000000000000000000000000001",
     "000000000000000000000002", 1,
     "416e79207375626d697373696f6e20746f20746865204945544620696e74656e"
     "6465642062792074686520436f6e7472696275746f7220666f72207075626c69"
     "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446"
     "20496e7465726e65742d4472616674206f722052464320616e6420616e792073"
     "746174656d656e74206d6164652077697468696e2074686520636f6e74657874"
     "206f6620616e204945544620616374697669747920697320636f6e7369646572"
     "656420616e20224945544620436f6e747269627574696f6e222e205375636820"
     "73746174656d656e747320696e636c756465206f72616c2073746174656d656e"
     "747320696e20494554462073657373696f6e732c2061732077656c6c20617320"
     "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361"
     "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c"
     "207768696368206172652061646472657373656420746f",
     "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec"
     "2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d"
     "4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950"
     "42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85a"
     "d00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259d"
     "c4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b"
     "0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c"
     "cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0b"
     "c39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f"
     "5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e6"
     "98ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab"
     "7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221"},
    {"1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
     "000000000000000000000002", 42,
     "2754776173206272696c6c69672c20616e642074686520736c6974687920746f"
     "7665730a446964206779726520616e642067696d626c6520696e207468652077"
     "6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665"
     "732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
     "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf"
     "166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb"
     "f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77"
     "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"},
};

/* RFC 8439 A.1 #2-#5: nonzero counter, a key with its last byte (and
 * byte 1) set, and a nonzero nonce. */
static void test_chacha_block_a1(void) {
  for (usz v = 0; v < 4; v++) {
    u8 key[32], nonce[12], ks[64], want[64];
    uh(c8439_a1[v].key, key);
    uh(c8439_a1[v].nonce, nonce);
    uh(c8439_a1[v].ks, want);
    chacha20_block(key, c8439_a1[v].counter, nonce, ks);
    for (usz i = 0; i < 64; i++) {
      CHECK(ks[i] == want[i]);
    }
  }
}

/* RFC 8439 A.2 #2-#3: multi-block messages (375 and 127 octets, the last
 * block partial) from counters 1 and 42 through chacha20_xor. */
static void test_chacha_encrypt_a2(void) {
  for (usz v = 0; v < 2; v++) {
    u8  key[32], nonce[12], pt[375], want[375], ct[375];
    usz n;
    uh(c8439_a2[v].key, key);
    uh(c8439_a2[v].nonce, nonce);
    n = uh(c8439_a2[v].pt, pt);
    CHECK(uh(c8439_a2[v].ct, want) == n);
    chacha_ctx c = {key, nonce, c8439_a2[v].counter};
    chacha20_xor(&c, wired_span_of(pt, n), ct);
    for (usz i = 0; i < n; i++) {
      CHECK(ct[i] == want[i]);
    }
  }
}

void test_chacha20(void) {
  test_chacha_block();
  test_chacha_encrypt();
  test_chacha_quarter_round();
  test_chacha_quarter_round_state();
  test_chacha_block_2_3_2();
  test_chacha_poly_key_2_6_2();
  test_chacha_block_a1();
  test_chacha_encrypt_a2();
}
