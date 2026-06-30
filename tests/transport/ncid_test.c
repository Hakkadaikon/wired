#include "test.h"

static void test_ncid_roundtrip(void) {
  quic_ncid_frame in = {.seq = 5, .retire_prior_to = 2, .cid_len = 4};
  for (usz i = 0; i < 4; i++) in.cid[i] = (u8)(0xA0 + i);
  for (usz i = 0; i < QUIC_NCID_TOKEN; i++) in.token[i] = (u8)(i * 3);
  u8  buf[64];
  usz w = quic_ncid_encode(buf, sizeof(buf), &in);
  CHECK(w != 0 && buf[0] == QUIC_FRAME_NEW_CID);

  quic_ncid_frame out;
  usz             r = quic_ncid_decode(buf, w, &out);
  CHECK(r == w && out.seq == 5 && out.retire_prior_to == 2);
  CHECK(out.cid_len == 4 && out.cid[0] == 0xA0 && out.cid[3] == 0xA3);
  CHECK(out.token[0] == 0 && out.token[15] == 45);
}

static void test_ncid_invalid_and_truncated(void) {
  u8 buf[64];
  /* retire_prior_to > seq is rejected */
  quic_ncid_frame bad = {.seq = 1, .retire_prior_to = 9, .cid_len = 0};
  CHECK(quic_ncid_encode(buf, sizeof(buf), &bad) == 0);

  quic_ncid_frame ok = {.seq = 3, .retire_prior_to = 0, .cid_len = 8};
  usz             w  = quic_ncid_encode(buf, sizeof(buf), &ok);
  quic_ncid_frame out;
  CHECK(quic_ncid_decode(buf, w - 1, &out) == 0); /* token cut short */
}

void test_ncid(void) {
  test_ncid_roundtrip();
  test_ncid_invalid_and_truncated();
}
