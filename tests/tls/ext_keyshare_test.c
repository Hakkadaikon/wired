#include "test.h"

/* --- encode: x25519 (32-byte key) ---------------------------------------- */

static void test_ext_key_share_wire_x25519(void) {
  u8 pub[32], buf[96];
  for (usz i = 0; i < 32; i++) pub[i] = (u8)(i + 1);
  usz w = quic_tls_ext_key_share(buf, sizeof(buf), QUIC_GROUP_X25519, pub, 32);
  CHECK(w == 42);
  /* RFC 8446 4.2.8 header bytes */
  CHECK(buf[0] == 0x00 && buf[1] == 0x33); /* type */
  CHECK(buf[2] == 0x00 && buf[3] == 38);   /* ext_len */
  CHECK(buf[4] == 0x00 && buf[5] == 36);   /* shares_len */
  CHECK(buf[6] == 0x00 && buf[7] == 0x1d); /* x25519 */
  CHECK(buf[8] == 0x00 && buf[9] == 32);   /* key_exchange len */
  CHECK(buf[10] == 1 && buf[41] == 32);    /* key contents */
}

/* --- encode: secp256r1 (65-byte key) ------------------------------------- */

static void test_ext_key_share_wire_secp256r1(void) {
  u8 pub[65], buf[96];
  for (usz i = 0; i < 65; i++) pub[i] = (u8)(i + 1);
  usz w =
      quic_tls_ext_key_share(buf, sizeof(buf), QUIC_GROUP_SECP256R1, pub, 65);
  CHECK(w == 75); /* 4 (type+ext_len) + 2 (shares_len) + 4 (entry hdr) + 65 */
  CHECK(buf[0] == 0x00 && buf[1] == 0x33);
  CHECK(buf[2] == 0x00 && buf[3] == 71);   /* ext_len = 2 + 4 + 65 */
  CHECK(buf[4] == 0x00 && buf[5] == 69);   /* shares_len = 4 + 65 */
  CHECK(buf[6] == 0x00 && buf[7] == 0x17); /* secp256r1 */
  CHECK(buf[8] == 0x00 && buf[9] == 65);   /* key_exchange len */
  CHECK(buf[10] == 1 && buf[74] == 65);    /* key contents */
}

static void test_ext_key_share_cap_guard(void) {
  u8 pub[32] = {0}, buf[41];
  CHECK(
      quic_tls_ext_key_share(buf, sizeof(buf), QUIC_GROUP_X25519, pub, 32) ==
      0);
}

/* --- parse: single KeyShareEntry (ServerHello) --------------------------- */

static void test_ext_key_share_parse_x25519(void) {
  u8  pub[32], got[32], buf[96];
  u16 group = 0;
  usz got_len;
  for (usz i = 0; i < 32; i++) pub[i] = (u8)(0xA0 + i);
  quic_tls_ext_key_share(buf, sizeof(buf), QUIC_GROUP_X25519, pub, 32);
  /* parse the KeyShareEntry that begins at buf+6 (group/ke_len/key) */
  CHECK(
      quic_tls_ext_key_share_parse(buf + 6, 36, &group, got, &got_len, 32) ==
      1);
  CHECK(group == QUIC_GROUP_X25519 && got_len == 32);
  for (usz i = 0; i < 32; i++) CHECK(got[i] == pub[i]);
}

static void test_ext_key_share_parse_secp256r1(void) {
  u8  pub[65], got[65], buf[96];
  u16 group = 0;
  usz got_len;
  for (usz i = 0; i < 65; i++) pub[i] = (u8)(0x30 + i);
  quic_tls_ext_key_share(buf, sizeof(buf), QUIC_GROUP_SECP256R1, pub, 65);
  CHECK(
      quic_tls_ext_key_share_parse(buf + 6, 69, &group, got, &got_len, 65) ==
      1);
  CHECK(group == QUIC_GROUP_SECP256R1 && got_len == 65);
  for (usz i = 0; i < 65; i++) CHECK(got[i] == pub[i]);
}

static void test_ext_key_share_parse_guards(void) {
  u8  got[65];
  u16 group;
  usz got_len;
  u8  wrong_len_x25519[36]   = {0x00, 0x1d, 0x00, 31}; /* x25519, bad len */
  u8  wrong_len_secp256r1[6] = {0x00, 0x17, 0x00, 64}; /* secp256r1, bad len */
  u8  unknown_group[36]      = {0x12, 0x34, 0x00, 32}; /* unrecognised group */
  CHECK(
      quic_tls_ext_key_share_parse(
          wrong_len_x25519, 36, &group, got, &got_len, 65) == 0);
  CHECK(
      quic_tls_ext_key_share_parse(
          wrong_len_secp256r1, 6, &group, got, &got_len, 65) == 0);
  CHECK(
      quic_tls_ext_key_share_parse(
          unknown_group, 36, &group, got, &got_len, 65) == 0);
  /* truncated: header claims a key but n does not have room for it */
  CHECK(
      quic_tls_ext_key_share_parse(
          wrong_len_x25519, 35, &group, got, &got_len, 65) == 0);
  /* caller's buffer is too small for the entry's key */
  {
    u8 x25519_entry[36] = {0x00, 0x1d, 0x00, 32};
    CHECK(
        quic_tls_ext_key_share_parse(
            x25519_entry, 36, &group, got, &got_len, 16) == 0);
  }
}

/* --- scan: ClientHello KeyShareEntry list, filtered by wanted group ------ */

/* RFC 8446 4.2.8: a ClientHello key_share is client_shares<2> then a list of
 * KeyShareEntry. curl/quiche send several groups and x25519 is not always
 * first; scan the list and pull the wanted group's key out from any
 * position. */
static void test_ext_key_share_scan_not_first(void) {
  u8  got[65];
  usz got_len;
  /* shares_len(2)=72 | secp256r1(0x0017) len 32 [32 bytes, deliberately the
   * wrong length so it's skipped as malformed-for-its-group] ... */
  u8 b[2 + 36 + 36];
  b[0] = 0x00;
  b[1] = 72;
  b[2] = 0x00;
  b[3] = 0x99; /* an unrecognised group entry, skipped */
  b[4] = 0x00;
  b[5] = 32;
  for (usz i = 0; i < 32; i++) b[6 + i] = 0xEE;
  b[38] = 0x00;
  b[39] = 0x1d;
  b[40] = 0x00;
  b[41] = 32; /* x25519 entry */
  for (usz i = 0; i < 32; i++) b[42 + i] = (u8)(0x50 + i);
  CHECK(
      quic_tls_ext_key_share_scan(
          b, sizeof(b), QUIC_GROUP_X25519, got, &got_len, sizeof(got)) == 1);
  CHECK(got_len == 32);
  for (usz i = 0; i < 32; i++) CHECK(got[i] == (u8)(0x50 + i));
}

static void test_ext_key_share_scan_first(void) {
  u8  got[65];
  usz got_len;
  u8  b[2 + 36];
  b[0] = 0x00;
  b[1] = 36;
  b[2] = 0x00;
  b[3] = 0x1d;
  b[4] = 0x00;
  b[5] = 32;
  for (usz i = 0; i < 32; i++) b[6 + i] = (u8)(0x70 + i);
  CHECK(
      quic_tls_ext_key_share_scan(
          b, sizeof(b), QUIC_GROUP_X25519, got, &got_len, sizeof(got)) == 1);
  CHECK(got_len == 32);
  for (usz i = 0; i < 32; i++) CHECK(got[i] == (u8)(0x70 + i));
}

/* Both x25519 and secp256r1 offered; scanning for either finds it. */
static void test_ext_key_share_scan_both_offered(void) {
  u8  got[65];
  usz got_len;
  u8  b[2 + 36 + 69];
  b[0] = 0x00;
  b[1] = 36 + 69;
  b[2] = 0x00;
  b[3] = 0x1d;
  b[4] = 0x00;
  b[5] = 32;
  for (usz i = 0; i < 32; i++) b[6 + i] = (u8)(0x11 + i);
  b[38] = 0x00;
  b[39] = 0x17;
  b[40] = 0x00;
  b[41] = 65;
  for (usz i = 0; i < 65; i++) b[42 + i] = (u8)(0x22 + i);
  CHECK(
      quic_tls_ext_key_share_scan(
          b, sizeof(b), QUIC_GROUP_SECP256R1, got, &got_len, sizeof(got)) == 1);
  CHECK(got_len == 65);
  for (usz i = 0; i < 65; i++) CHECK(got[i] == (u8)(0x22 + i));
  CHECK(
      quic_tls_ext_key_share_scan(
          b, sizeof(b), QUIC_GROUP_X25519, got, &got_len, sizeof(got)) == 1);
  CHECK(got_len == 32);
  for (usz i = 0; i < 32; i++) CHECK(got[i] == (u8)(0x11 + i));
}

static void test_ext_key_share_scan_absent(void) {
  u8  got[65];
  usz got_len;
  u8  b[2 + 36];
  b[0] = 0x00;
  b[1] = 36;
  b[2] = 0x00;
  b[3] = 0x17; /* secp256r1 only */
  b[4] = 0x00;
  b[5] = 32; /* wrong length for secp256r1 anyway */
  for (usz i = 0; i < 32; i++) b[6 + i] = 0xEE;
  CHECK(
      quic_tls_ext_key_share_scan(
          b, sizeof(b), QUIC_GROUP_X25519, got, &got_len, sizeof(got)) == 0);
}

/* A truncated key_exchange length must fail, not read past n. */
static void test_ext_key_share_scan_oob(void) {
  u8  got[65];
  usz got_len;
  u8  b[2 + 6];
  b[0] = 0x00;
  b[1] = 36; /* claims 36 bytes of entries, only 6 present */
  b[2] = 0x00;
  b[3] = 0x1d;
  b[4] = 0x00;
  b[5] = 32;
  CHECK(
      quic_tls_ext_key_share_scan(
          b, sizeof(b), QUIC_GROUP_X25519, got, &got_len, sizeof(got)) == 0);
}

void test_ext_keyshare(void) {
  test_ext_key_share_wire_x25519();
  test_ext_key_share_wire_secp256r1();
  test_ext_key_share_cap_guard();
  test_ext_key_share_parse_x25519();
  test_ext_key_share_parse_secp256r1();
  test_ext_key_share_parse_guards();
  test_ext_key_share_scan_not_first();
  test_ext_key_share_scan_first();
  test_ext_key_share_scan_both_offered();
  test_ext_key_share_scan_absent();
  test_ext_key_share_scan_oob();
}
