#include "test.h"

/* The token is deterministic for a key+CID, and distinct CIDs differ. */
static void test_sreset_token(void) {
  u8 key[SRESET_KEY];
  for (usz i = 0; i < SRESET_KEY; i++) key[i] = (u8)(i + 1);
  const u8 cid_a[4] = {1, 2, 3, 4};
  const u8 cid_b[4] = {1, 2, 3, 5};
  u8       ta[16], ta2[16], tb[16];
  sreset_token(key, cid_a, 4, ta);
  sreset_token(key, cid_a, 4, ta2);
  sreset_token(key, cid_b, 4, tb);
  for (usz i = 0; i < 16; i++) CHECK(ta[i] == ta2[i]); /* deterministic */
  int differ = 0;
  for (usz i = 0; i < 16; i++) differ |= (ta[i] != tb[i]);
  CHECK(differ); /* different CID -> different token */
}

/* A datagram ending in the token is detected; mismatches and short ones not. */
static void test_sreset_detect(void) {
  u8       key[SRESET_KEY] = {0};
  const u8 cid[8]          = {9, 8, 7, 6, 5, 4, 3, 2};
  u8       token[16];
  sreset_token(key, cid, 8, token);

  u8 pkt[40];
  for (usz i = 0; i < 24; i++) pkt[i] = (u8)i;         /* arbitrary prefix */
  for (usz i = 0; i < 16; i++) pkt[24 + i] = token[i]; /* trailing token */
  CHECK(sreset_detect(pkt, 40, token) == 1);

  pkt[39] ^= 0x01; /* corrupt the last token byte */
  CHECK(sreset_detect(pkt, 40, token) == 0);

  CHECK(sreset_detect(pkt, 8, token) == 0); /* too short for a token */
}

/* Fill with a fixed non-zero pattern so built packets are checkable. */
static int fill_pattern(u8* buf, usz len) {
  for (usz i = 0; i < len; i++) buf[i] = (u8)(0xAA + i);
  return 1;
}

/* sreset_size: below 3x the trigger, never below the minimum. */
static void test_sreset_size(void) {
  CHECK(sreset_size(4) == SRESET_MIN);    /* 3*4-1=11 < min: floor */
  CHECK(sreset_size(10) == 3 * 10 - 1);   /* 29 >= min: as computed */
  CHECK(sreset_size(1200) < 1200 * 3);    /* strictly under 3x */
  CHECK(sreset_size(1200) >= SRESET_MIN); /* still >= floor */
}

/* Built packets stay under 3x the trigger and end in the correct token. */
static void test_sreset_build(void) {
  u8       key[SRESET_KEY] = {0};
  const u8 cid[8]          = {1, 2, 3, 4, 5, 6, 7, 8};
  u8       want[SRESET_TOKEN];
  sreset_token(key, cid, 8, want);

  u8  out[128];
  usz out_len = 0;
  CHECK(sreset_build(key, cid, 8, 40, fill_pattern, out, 128, &out_len) == 1);
  CHECK(out_len < 40 * 3);
  CHECK(out_len >= SRESET_MIN);
  CHECK(ct_diff16(out + out_len - SRESET_TOKEN, want) == 0);

  /* out_cap smaller than the natural size clamps the packet down. */
  usz small_len = 0;
  CHECK(
      sreset_build(key, cid, 8, 1200, fill_pattern, out, 30, &small_len) == 1);
  CHECK(small_len == 30);

  /* out_cap below the minimum cannot carry a token: refused. */
  usz tiny_len = 0;
  CHECK(
      sreset_build(
          key, cid, 8, 1200, fill_pattern, out, SRESET_MIN - 1, &tiny_len) ==
      0);
}

/* Pinning: RFC 9000 10.3.3 / CVE-2024-2169-class loop-DoS -- the server's
 * reply cap, `min(out_cap, trigger_len - 1)` (srvrun_seal_stateless_reset),
 * must always leave the built reset strictly SMALLER than the triggering
 * datagram, across a spread of trigger sizes, so a reset can never itself
 * trigger a same-or-larger reset in an amplifying loop (V-0491). This pins
 * the cap arithmetic itself (sreset_build honors an out_cap smaller than
 * its natural size, per test_sreset_build above). */
static void test_sreset_size_strictly_below_trigger_len(void) {
  /* trigger sizes drawn from what the real caller ever passes:
   * srvrun_sreset_applies requires dg.n > SRESET_MIN, so trigger_len ==
   * SRESET_MIN is never reachable in production (and is correctly refused
   * by sreset_build's own out_cap-below-minimum gate, since cap =
   * trigger_len - 1 == SRESET_MIN - 1 there). */
  static const usz triggers[] = {
      SRESET_MIN + 1, SRESET_MIN + 2, 100, 1200, 65535};
  u8       key[SRESET_KEY] = {0};
  const u8 cid[8]          = {1, 2, 3, 4, 5, 6, 7, 8};
  for (usz i = 0; i < sizeof(triggers) / sizeof(triggers[0]); i++) {
    usz trig = triggers[i];
    usz cap  = u64_min(128, trig - 1); /* mirrors srvrun_seal_stateless_reset */
    u8  out[128];
    usz len = 0;
    CHECK(sreset_build(key, cid, 8, trig, fill_pattern, out, cap, &len) == 1);
    CHECK(len < trig);
  }
}

void test_sreset(void) {
  test_sreset_token();
  test_sreset_detect();
  test_sreset_size();
  test_sreset_build();
  test_sreset_size_strictly_below_trigger_len();
}
