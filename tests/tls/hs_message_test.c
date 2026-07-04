#include "tls/handshake/core/tls/hs_message.h"

#include "test.h"

/* Header present but body incomplete -> not ready. */
static void test_hs_message_short(void) {
  usz n = 999;
  /* declares 3-byte body, only 2 supplied */
  CHECK(
      quic_hs_message_ready(
          (const u8*)"\x01\x00\x00\x03"
                     "ab",
          6, &n) == 0);
  CHECK(n == 999); /* untouched */
  /* fewer than 4 header bytes */
  CHECK(quic_hs_message_ready((const u8*)"\x01\x00", 2, &n) == 0);
}

/* Exactly one complete message. */
static void test_hs_message_exact(void) {
  usz n = 0;
  CHECK(
      quic_hs_message_ready(
          (const u8*)"\x01\x00\x00\x03"
                     "abc",
          7, &n) == 1);
  CHECK(n == 7);
}

/* Trailing bytes of the next message do not change msg_len. */
static void test_hs_message_extra(void) {
  usz n = 0;
  CHECK(
      quic_hs_message_ready(
          (const u8*)"\x01\x00\x00\x03"
                     "abc"
                     "\x02\x00\x00\x00",
          11, &n) == 1);
  CHECK(n == 7);
}

/* Type byte is the first byte. */
static void test_hs_message_type(void) {
  CHECK(quic_hs_message_type((const u8*)"\x0b\x00\x00\x00") == 0x0b);
}

void test_hs_message(void) {
  test_hs_message_short();
  test_hs_message_exact();
  test_hs_message_extra();
  test_hs_message_type();
}
