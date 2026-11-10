#include "test.h"

static void test_retry_roundtrip(void) {
  const u8 dcid[3]  = {0xD0, 0xD1, 0xD2};
  const u8 scid[2]  = {0x50, 0x51};
  const u8 token[5] = {0x10, 0x11, 0x12, 0x13, 0x14};
  u8       tag[RETRY_TAG_LEN];
  for (usz i = 0; i < RETRY_TAG_LEN; i++) {
    tag[i] = (u8)(0xA0 + i);
  }

  u8         buf[64];
  retry_desc rd = {
      1, wired_span_of(dcid, 3), wired_span_of(scid, 2),
      wired_span_of(token, 5), tag};
  usz w = retry_build(buf, sizeof(buf), &rd);
  CHECK(w == 5 + 1 + 3 + 1 + 2 + 5 + RETRY_TAG_LEN);
  CHECK(buf[0] == 0xF0 && buf[4] == 1); /* type Retry, version 1 */

  retry_packet r;
  usz          used = retry_parse(buf, w, &r);
  CHECK(used == w);
  CHECK(r.version == 1 && r.dcid_len == 3 && r.scid_len == 2);
  CHECK(r.dcid[2] == 0xD2 && r.scid[0] == 0x50);
  CHECK(r.token_len == 5 && r.token[0] == 0x10 && r.token[4] == 0x14);
  CHECK(r.tag[0] == 0xA0 && r.tag[15] == 0xAF);
}

static void test_retry_truncated(void) {
  const u8   dcid[1]            = {0x01};
  const u8   scid[1]            = {0x02};
  const u8   token[1]           = {0x03};
  u8         tag[RETRY_TAG_LEN] = {0};
  u8         buf[64];
  retry_desc rd = {
      1, wired_span_of(dcid, 1), wired_span_of(scid, 1),
      wired_span_of(token, 1), tag};
  usz w = retry_build(buf, sizeof(buf), &rd);
  CHECK(w != 0);

  /* w - 1 still parses: the token is variable-length, so dropping a trailing
   * byte just yields a shorter (here zero-length) token. To force a failure
   * the buffer must be too small to even hold byte0..version + a CID + tag. */
  retry_packet r;
  CHECK(retry_parse(buf, 6, &r) == 0); /* too small for header + tag */
  CHECK(retry_parse(buf, RETRY_TAG_LEN + 6, &r) == 0); /* CID len overruns */
  CHECK(retry_build(buf, 4, &rd) == 0);
}

static void test_vneg_roundtrip(void) {
  const u8  dcid[2] = {0xC0, 0xC1};
  const u8  scid[3] = {0x70, 0x71, 0x72};
  const u32 vers[2] = {0x00000001, 0x6B3343CF}; /* v1 and a GREASE-ish value */

  u8        buf[64];
  vneg_desc vd = {wired_span_of(dcid, 2), wired_span_of(scid, 3), vers, 2};
  usz       w  = vneg_build(buf, sizeof(buf), &vd);
  CHECK(w == 5 + 1 + 2 + 1 + 3 + 2 * 4);
  /* RFC 9000 17.2.1: the server SHOULD set 0x40 so VN looks like QUIC */
  CHECK(buf[0] == 0xc0);
  CHECK(
      buf[1] == 0 && buf[2] == 0 && buf[3] == 0 && buf[4] == 0); /* Version 0 */

  vneg_packet v;
  usz         used = vneg_parse(buf, w, &v);
  CHECK(used == w);
  CHECK(v.dcid_len == 2 && v.scid_len == 3 && v.count == 2);
  CHECK(v.dcid[1] == 0xC1 && v.scid[2] == 0x72);
  /* versions view is big-endian 4-byte groups */
  CHECK(v.versions[3] == 0x01);
  CHECK(v.versions[4] == 0x6B && v.versions[7] == 0xCF);
}

/* The VN response swaps the received DCID/SCID (RFC 8999 6) so the peer sees
 * its own connection ID as the destination. */
static void test_vneg_respond_swap(void) {
  const u8  recv_dcid[2] = {0xAA, 0xBB};
  const u8  recv_scid[3] = {0x11, 0x22, 0x33};
  const u32 vers[1]      = {0x00000001};
  u8        buf[64];
  vneg_desc rv = {
      wired_span_of(recv_dcid, 2), wired_span_of(recv_scid, 3), vers, 1};
  usz w = vneg_respond(buf, sizeof(buf), &rv);
  CHECK(w != 0);

  vneg_packet v;
  CHECK(vneg_parse(buf, w, &v) == w);
  /* response DCID is the received SCID; response SCID is the received DCID */
  CHECK(v.dcid_len == 3 && v.dcid[0] == 0x11 && v.dcid[2] == 0x33);
  CHECK(v.scid_len == 2 && v.scid[0] == 0xAA && v.scid[1] == 0xBB);
}

static void test_vneg_bad(void) {
  const u8  dcid[1] = {0x01};
  const u8  scid[1] = {0x02};
  const u32 vers[1] = {0x00000001};
  u8        buf[64];
  vneg_desc v0 = {wired_span_of(dcid, 1), wired_span_of(scid, 1), vers, 0};
  vneg_desc v1 = {wired_span_of(dcid, 1), wired_span_of(scid, 1), vers, 1};
  /* count 0 must fail to build */
  CHECK(vneg_build(buf, sizeof(buf), &v0) == 0);

  usz w = vneg_build(buf, sizeof(buf), &v1);
  CHECK(w != 0);
  buf[4] = 1; /* corrupt Version field to non-zero */
  vneg_packet v;
  CHECK(vneg_parse(buf, w, &v) == 0);
}

/* RFC 8999 6 / RFC 9000 17.2.1: a VN packet from the peer is rejected when
 * shorter than byte0+Version+two CID lengths, short-form, carrying a CID
 * over 20 bytes, cut inside the SCID length, or listing no version. */
static void test_vneg_parse_rejects_malformed(void) {
  u8          b[40] = {0xc0, 0, 0, 0, 0, 0, 0};
  vneg_packet v;
  CHECK(vneg_parse(b, 6, &v) == 0); /* under 7 bytes */
  CHECK(vneg_parse(b, 7, &v) == 0); /* both CIDs empty, no versions */
  b[5] = WIRED_MAX_CID_LEN + 1;
  CHECK(vneg_parse(b, sizeof(b), &v) == 0); /* DCID over 20 */
  b[5] = 1;
  CHECK(vneg_parse(b, 7, &v) == 0); /* SCID length byte missing */
  b[0] = 0x40;
  CHECK(vneg_parse(b, sizeof(b), &v) == 0); /* short header form */
}

/* RFC 9000 17.2.5: a peer Retry carrying a DCID over 20 bytes, or ending
 * before its SCID length byte, is rejected. */
static void test_retry_parse_rejects_bad_cids(void) {
  u8           b[48] = {0xF0, 0, 0, 0, 1};
  retry_packet r;
  b[5] = WIRED_MAX_CID_LEN + 1;
  CHECK(retry_parse(b, sizeof(b), &r) == 0);
  b[5] = WIRED_MAX_CID_LEN; /* DCID fills bytes 6..25, SCID length at 26 */
  CHECK(retry_parse(b, 26, &r) == 0);
}

void test_packet2(void) {
  test_vneg_parse_rejects_malformed();
  test_retry_parse_rejects_bad_cids();
  test_retry_roundtrip();
  test_retry_truncated();
  test_vneg_roundtrip();
  test_vneg_respond_swap();
  test_vneg_bad();
}
