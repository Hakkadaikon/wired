#include "test.h"

/* The token is deterministic for a key+CID, and distinct CIDs differ. */
static void test_sreset_token(void) {
  u8 key[QUIC_SRESET_KEY];
  for (usz i = 0; i < QUIC_SRESET_KEY; i++) key[i] = (u8)(i + 1);
  const u8 cid_a[4] = {1, 2, 3, 4};
  const u8 cid_b[4] = {1, 2, 3, 5};
  u8       ta[16], ta2[16], tb[16];
  quic_sreset_token(key, cid_a, 4, ta);
  quic_sreset_token(key, cid_a, 4, ta2);
  quic_sreset_token(key, cid_b, 4, tb);
  for (usz i = 0; i < 16; i++) CHECK(ta[i] == ta2[i]); /* deterministic */
  int differ = 0;
  for (usz i = 0; i < 16; i++) differ |= (ta[i] != tb[i]);
  CHECK(differ); /* different CID -> different token */
}

/* A datagram ending in the token is detected; mismatches and short ones not. */
static void test_sreset_detect(void) {
  u8       key[QUIC_SRESET_KEY] = {0};
  const u8 cid[8]               = {9, 8, 7, 6, 5, 4, 3, 2};
  u8       token[16];
  quic_sreset_token(key, cid, 8, token);

  u8 pkt[40];
  for (usz i = 0; i < 24; i++) pkt[i] = (u8)i;         /* arbitrary prefix */
  for (usz i = 0; i < 16; i++) pkt[24 + i] = token[i]; /* trailing token */
  CHECK(quic_sreset_detect(pkt, 40, token) == 1);

  pkt[39] ^= 0x01; /* corrupt the last token byte */
  CHECK(quic_sreset_detect(pkt, 40, token) == 0);

  CHECK(quic_sreset_detect(pkt, 8, token) == 0); /* too short for a token */
}

void test_sreset(void) {
  test_sreset_token();
  test_sreset_detect();
}
