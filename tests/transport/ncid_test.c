#include "test.h"

static void test_ncid_roundtrip(void) {
  ncid_frame in = {.seq = 5, .retire_prior_to = 2, .cid_len = 4};
  for (usz i = 0; i < 4; i++) {
    in.cid[i] = (u8)(0xA0 + i);
  }
  for (usz i = 0; i < NCID_TOKEN; i++) {
    in.token[i] = (u8)(i * 3);
  }
  u8  buf[64];
  usz w = ncid_encode(buf, sizeof(buf), &in);
  CHECK(w != 0 && buf[0] == FRAME_NEW_CID);

  ncid_frame out;
  usz        r = ncid_decode(buf, w, &out);
  CHECK(r == w && out.seq == 5 && out.retire_prior_to == 2);
  CHECK(out.cid_len == 4 && out.cid[0] == 0xA0 && out.cid[3] == 0xA3);
  CHECK(out.token[0] == 0 && out.token[15] == 45);
}

static void test_ncid_invalid_and_truncated(void) {
  u8 buf[64];
  /* retire_prior_to > seq is rejected */
  ncid_frame bad = {.seq = 1, .retire_prior_to = 9, .cid_len = 0};
  CHECK(ncid_encode(buf, sizeof(buf), &bad) == 0);

  ncid_frame ok = {.seq = 3, .retire_prior_to = 0, .cid_len = 8};
  usz        w  = ncid_encode(buf, sizeof(buf), &ok);
  ncid_frame out;
  CHECK(ncid_decode(buf, w - 1, &out) == 0); /* token cut short */
}

/* CVE-2026-44436 class (quicly oob-write via NEW_CONNECTION_ID with an
 * over-max CID length): a raw wire buffer whose length byte exceeds
 * NCID_MAX_LEN (20, RFC 9000 19.15) must be rejected by ncid_decode before
 * any copy into the fixed 20-byte cid buffer, even though seq/retire_prior_to
 * are otherwise well-formed. */
static void test_ncid_decode_rejects_over_max_len(void) {
  u8  buf[64];
  usz w    = 0;
  buf[w++] = FRAME_NEW_CID;
  buf[w++] = 0;  /* seq = 0 */
  buf[w++] = 0;  /* retire_prior_to = 0 */
  buf[w++] = 21; /* cid length byte: NCID_MAX_LEN + 1 */
  for (int i = 0; i < 21; i++) {
    buf[w++] = 0xAA;
  }
  for (int i = 0; i < NCID_TOKEN; i++) {
    buf[w++] = 0;
  }

  ncid_frame out;
  CHECK(ncid_decode(buf, w, &out) == 0);
}

/* RFC 9000 19.15: a zero-length Connection ID is a FRAME_ENCODING_ERROR --
 * ncid_decode rejects it. */
static void test_ncid_decode_rejects_zero_len(void) {
  u8  buf[64];
  usz w    = 0;
  buf[w++] = FRAME_NEW_CID;
  buf[w++] = 1; /* seq = 1 */
  buf[w++] = 0; /* retire_prior_to = 0 */
  buf[w++] = 0; /* cid length byte: zero */
  for (int i = 0; i < NCID_TOKEN; i++) {
    buf[w++] = 0;
  }

  ncid_frame out;
  CHECK(ncid_decode(buf, w, &out) == 0);
}

/* RFC 9312 2.6 routing byte: every core 0..255 round-trips under a keygen'd
 * key, the mask depends on cid[1..4] (flipping cid[4] changes it for some
 * core), and a CID shorter than NCID_ROUTE_MIN_LEN is refused. */
static void test_ncid_route_roundtrip(void) {
  ncid_route_key k;
  u8             cid[8] = {0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  usz            moved  = 0;
  CHECK(ncid_route_keygen(&k) == 1);
  CHECK((k.k[1] & 1) == 1 && (k.k[2] & 1) == 1);
  for (u32 core = 0; core < 256; core++) {
    CHECK(ncid_route_encode(cid, sizeof cid, (u8)core, &k) == 0);
    CHECK(ncid_route_decode(cid, &k) == core);
    cid[4] ^= 0x01;
    moved += ncid_route_decode(cid, &k) != core;
    cid[4] ^= 0x01;
    cid[1] = (u8)(cid[1] + 1);
  }
  CHECK(moved > 200);
  CHECK(ncid_route_encode(cid, NCID_ROUTE_MIN_LEN - 1, 1, &k) < 0);
}

/* RFC 9000 19.15: type, seq, retire_prior_to, length, CID, 16-byte token.
 * An encode into any cap shorter than the frame fails, and a decode of any
 * strict prefix fails at whichever field it cuts. */
static void test_ncid_every_prefix_rejected(void) {
  ncid_frame in = {.seq = 2, .retire_prior_to = 1, .cid_len = 4};
  ncid_frame out;
  u8         buf[64];
  usz        w = ncid_encode(buf, sizeof(buf), &in);
  CHECK(w == 4 + 4 + NCID_TOKEN);
  for (usz c = 0; c < w; c++) {
    CHECK(ncid_encode(buf, c, &in) == 0);
  }
  ncid_encode(buf, sizeof(buf), &in);
  for (usz n = 1; n < w; n++) {
    CHECK(ncid_decode(buf, n, &out) == 0);
  }
}

void test_ncid(void) {
  test_ncid_every_prefix_rejected();
  test_ncid_route_roundtrip();
  test_ncid_roundtrip();
  test_ncid_invalid_and_truncated();
  test_ncid_decode_rejects_over_max_len();
  test_ncid_decode_rejects_zero_len();
}
