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

/* Fill with a fixed non-zero pattern so built packets are checkable. */
static int fill_pattern(u8* buf, usz len) {
  for (usz i = 0; i < len; i++) buf[i] = (u8)(0xAA + i);
  return 1;
}

/* quic_sreset_size: below 3x the trigger, never below the minimum. */
static void test_sreset_size(void) {
  CHECK(quic_sreset_size(4) == QUIC_SRESET_MIN);    /* 3*4-1=11 < min: floor */
  CHECK(quic_sreset_size(10) == 3 * 10 - 1);        /* 29 >= min: as computed */
  CHECK(quic_sreset_size(1200) < 1200 * 3);         /* strictly under 3x */
  CHECK(quic_sreset_size(1200) >= QUIC_SRESET_MIN); /* still >= floor */
}

/* Built packets stay under 3x the trigger and end in the correct token. */
static void test_sreset_build(void) {
  u8       key[QUIC_SRESET_KEY] = {0};
  const u8 cid[8]               = {1, 2, 3, 4, 5, 6, 7, 8};
  u8       want[QUIC_SRESET_TOKEN];
  quic_sreset_token(key, cid, 8, want);

  u8  out[128];
  usz out_len = 0;
  CHECK(
      quic_sreset_build(key, cid, 8, 40, fill_pattern, out, 128, &out_len) ==
      1);
  CHECK(out_len < 40 * 3);
  CHECK(out_len >= QUIC_SRESET_MIN);
  CHECK(quic_ct_diff16(out + out_len - QUIC_SRESET_TOKEN, want) == 0);

  /* out_cap smaller than the natural size clamps the packet down. */
  usz small_len = 0;
  CHECK(
      quic_sreset_build(key, cid, 8, 1200, fill_pattern, out, 30, &small_len) ==
      1);
  CHECK(small_len == 30);

  /* out_cap below the minimum cannot carry a token: refused. */
  usz tiny_len = 0;
  CHECK(
      quic_sreset_build(
          key, cid, 8, 1200, fill_pattern, out, QUIC_SRESET_MIN - 1,
          &tiny_len) == 0);
}

void test_sreset(void) {
  test_sreset_token();
  test_sreset_detect();
  test_sreset_size();
  test_sreset_build();
}
