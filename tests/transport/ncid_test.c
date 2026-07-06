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

static void test_ncid_worker_roundtrip(void) {
  for (u32 w = 0; w < 8; w++) {
    u8 cid[8] = {0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    CHECK(quic_ncid_worker_encode(cid, sizeof(cid), 3, w) == 0);
    CHECK(quic_ncid_worker_decode(cid, sizeof(cid), 3) == (int)w);
    /* low 5 bits of cid[0] and the rest of the CID are untouched */
    CHECK((cid[0] & 0x1F) == (0xFF & 0x1F));
    CHECK(cid[1] == 0x11 && cid[7] == 0x77);
  }
}

static void test_ncid_worker_minmax_bits(void) {
  u8 cid1[4] = {0};
  CHECK(quic_ncid_worker_encode(cid1, sizeof(cid1), 1, 1) == 0);
  CHECK(quic_ncid_worker_decode(cid1, sizeof(cid1), 1) == 1);

  u8 cid8[4] = {0};
  CHECK(quic_ncid_worker_encode(cid8, sizeof(cid8), 8, 200) == 0);
  CHECK(quic_ncid_worker_decode(cid8, sizeof(cid8), 8) == 200);
}

static void test_ncid_worker_invalid_bits(void) {
  u8 cid[4] = {0};
  CHECK(quic_ncid_worker_encode(cid, sizeof(cid), 0, 0) < 0);
  CHECK(quic_ncid_worker_encode(cid, sizeof(cid), 9, 0) < 0);
  CHECK(quic_ncid_worker_encode(cid, sizeof(cid), -1, 0) < 0);
  CHECK(quic_ncid_worker_decode(cid, sizeof(cid), 0) < 0);
  CHECK(quic_ncid_worker_decode(cid, sizeof(cid), 9) < 0);
  CHECK(quic_ncid_worker_decode(cid, sizeof(cid), -1) < 0);
}

static void test_ncid_worker_zero_len(void) {
  u8 cid[4] = {0};
  CHECK(quic_ncid_worker_encode(cid, 0, 3, 1) < 0);
  CHECK(quic_ncid_worker_decode(cid, 0, 3) < 0);
}

static void test_ncid_worker_masks_oversize_index(void) {
  /* bits=2 keeps only the low 2 bits of worker_idx: masked, not rejected. */
  u8 cid[4] = {0};
  CHECK(quic_ncid_worker_encode(cid, sizeof(cid), 2, 7) == 0);
  CHECK(quic_ncid_worker_decode(cid, sizeof(cid), 2) == 3);
}

void test_ncid(void) {
  test_ncid_roundtrip();
  test_ncid_invalid_and_truncated();
  test_ncid_worker_roundtrip();
  test_ncid_worker_minmax_bits();
  test_ncid_worker_invalid_bits();
  test_ncid_worker_zero_len();
  test_ncid_worker_masks_oversize_index();
}
