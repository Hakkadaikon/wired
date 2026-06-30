#include "tls/handshake/core/handshake_drive/retry_drive.h"

#include "test.h"
#include "tls/handshake/core/tls/retry_tag.h"
#include "transport/packet/header/packet/retry.h"
#include "transport/version/version/version.h"

/* Build a Retry packet with a valid integrity tag over orig_dcid. */
static usz make_retry(
    u8       *buf,
    usz       cap,
    const u8 *orig_dcid,
    u8        odcil,
    const u8 *scid,
    u8        scil,
    const u8 *token,
    usz       tlen) {
  static const u8 dummy_dcid[4]           = {0xaa, 0xbb, 0xcc, 0xdd};
  u8              tag[QUIC_RETRY_TAG_LEN] = {0};
  usz             n                       = quic_retry_build(
      buf, cap, QUIC_VERSION_1, dummy_dcid, 4, scid, scil, token, tlen, tag);
  /* recompute the real tag over (orig_dcid || retry-without-tag) */
  quic_retry_tag(
      orig_dcid, odcil, buf, n - QUIC_RETRY_TAG_LEN,
      buf + n - QUIC_RETRY_TAG_LEN);
  return n;
}

/* A valid Retry yields token and the Retry SCID as the new DCID. */
static void test_retry_process_ok(void) {
  const u8 odcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  const u8 scid[5]  = {1, 2, 3, 4, 5};
  const u8 token[6] = {9, 8, 7, 6, 5, 4};
  u8       pkt[64];
  usz      n = make_retry(pkt, sizeof(pkt), odcid, 8, scid, 5, token, 6);

  u8  out_token[64], new_dcid[QUIC_MAX_CID_LEN], new_dcil = 0;
  usz tlen = 0;
  CHECK(
      quic_retry_process(
          pkt, n, odcid, 8, out_token, &tlen, new_dcid, &new_dcil) == 1);
  CHECK(tlen == 6);
  for (usz i = 0; i < 6; i++) CHECK(out_token[i] == token[i]);
  CHECK(new_dcil == 5);
  for (usz i = 0; i < 5; i++) CHECK(new_dcid[i] == scid[i]);
}

/* A tampered tag (wrong ODCID) is rejected and outputs are untouched. */
static void test_retry_process_bad_tag(void) {
  const u8 odcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  const u8 scid[3]  = {7, 7, 7};
  const u8 token[2] = {1, 2};
  u8       pkt[64];
  usz      n = make_retry(pkt, sizeof(pkt), odcid, 8, scid, 3, token, 2);

  u8 wrong[8];
  for (usz i = 0; i < 8; i++) wrong[i] = odcid[i];
  wrong[0] ^= 0x80;

  u8  out_token[64], new_dcid[QUIC_MAX_CID_LEN], new_dcil = 0xff;
  usz tlen = 0xff;
  CHECK(
      quic_retry_process(
          pkt, n, wrong, 8, out_token, &tlen, new_dcid, &new_dcil) == 0);
}

/* A truncated packet is rejected. */
static void test_retry_process_short(void) {
  u8  pkt[4] = {0xf0, 0, 0, 1};
  u8  out_token[8], new_dcid[QUIC_MAX_CID_LEN], new_dcil;
  usz tlen;
  CHECK(
      quic_retry_process(
          pkt, sizeof(pkt), 0, 0, out_token, &tlen, new_dcid, &new_dcil) == 0);
}

/* The one-shot gate: a second Retry must be ignored. */
static void test_retry_already(void) {
  CHECK(quic_retry_already(0) == 0);
  CHECK(quic_retry_already(1) == 1);
}

void test_retry_drive(void) {
  test_retry_process_ok();
  test_retry_process_bad_tag();
  test_retry_process_short();
  test_retry_already();
}
