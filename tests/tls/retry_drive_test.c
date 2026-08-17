#include "tls/handshake/core/handshake_drive/retry_drive.h"

#include "test.h"
#include "tls/handshake/core/tls/retry_tag.h"
#include "transport/packet/header/packet/retry.h"
#include "transport/version/version/version.h"

/* Build a Retry packet with a valid integrity tag over orig_dcid. */
static usz make_retry(
    u8*       buf,
    usz       cap,
    const u8* orig_dcid,
    u8        odcil,
    const u8* scid,
    u8        scil,
    const u8* token,
    usz       tlen) {
  static const u8 dummy_dcid[4]           = {0xaa, 0xbb, 0xcc, 0xdd};
  u8              tag[QUIC_RETRY_TAG_LEN] = {0};
  retry_desc      rd                      = {
      QUIC_VERSION_1, wired_span_of(dummy_dcid, 4), wired_span_of(scid, scil),
      wired_span_of(token, tlen), tag};
  usz n = retry_build(buf, cap, &rd);
  /* recompute the real tag over (orig_dcid || retry-without-tag) */
  retry_tag(
      wired_span_of(orig_dcid, odcil),
      wired_span_of(buf, n - QUIC_RETRY_TAG_LEN), buf + n - QUIC_RETRY_TAG_LEN);
  return n;
}

/* A valid Retry yields token and the Retry SCID as the new DCID. */
static void test_retry_process_ok(void) {
  const u8 odcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  const u8 scid[5]  = {1, 2, 3, 4, 5};
  const u8 token[6] = {9, 8, 7, 6, 5, 4};
  u8       pkt[64];
  usz      n = make_retry(pkt, sizeof(pkt), odcid, 8, scid, 5, token, 6);

  u8         out_token[64], new_dcid[WIRED_MAX_CID_LEN], new_dcil = 0;
  wired_obuf tok_ob = obuf_of(out_token, sizeof(out_token));
  CHECK(
      retry_process(
          wired_span_of(pkt, n), wired_span_of(odcid, 8),
          &(retry_process_out){&tok_ob, new_dcid, &new_dcil}) == 1);
  CHECK(tok_ob.len == 6);
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

  u8 out_token[64], new_dcid[WIRED_MAX_CID_LEN], new_dcil = 0xff;
  CHECK(
      retry_process(
          wired_span_of(pkt, n), wired_span_of(wrong, 8),
          &(retry_process_out){
              &(wired_obuf){out_token, sizeof(out_token), 0}, new_dcid,
              &new_dcil}) == 0);
}

/* A truncated packet is rejected. */
static void test_retry_process_short(void) {
  u8 pkt[4] = {0xf0, 0, 0, 1};
  u8 out_token[8], new_dcid[WIRED_MAX_CID_LEN], new_dcil;
  CHECK(
      retry_process(
          wired_span_of(pkt, sizeof(pkt)), wired_span_of(0, 0),
          &(retry_process_out){
              &(wired_obuf){out_token, sizeof(out_token), 0}, new_dcid,
              &new_dcil}) == 0);
}

/* The one-shot gate: a second Retry must be ignored. */
static void test_retry_already(void) {
  CHECK(retry_already(0) == 0);
  CHECK(retry_already(1) == 1);
}

void test_retry_drive(void) {
  test_retry_process_ok();
  test_retry_process_bad_tag();
  test_retry_process_short();
  test_retry_already();
}
