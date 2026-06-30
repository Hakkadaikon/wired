#include "test.h"

/* RFC 9000 17.3: short header byte0 = 0x40 | spin<<5 | key_phase<<2 |
 * (pn_len-1), then the DCID (no length prefix) and pn_len big-endian
 * packet-number bytes. */
static void test_short_build(void) {
  const u8 dcid[4] = {0x11, 0x22, 0x33, 0x44};
  u8       buf[16];
  usz      w = quic_short_build(buf, sizeof(buf), dcid, 4, 1, 1, 0xABCD, 2);
  CHECK(w == 1 + 4 + 2);
  /* fixed bit set, spin (bit5) set, key_phase (bit2) set, pn_len-1 == 1 */
  CHECK(buf[0] == (0x40 | 0x20 | 0x04 | 0x01));
  CHECK(buf[1] == 0x11 && buf[4] == 0x44); /* DCID placed right after byte0 */
  CHECK(buf[5] == 0xAB && buf[6] == 0xCD); /* pn big-endian */
}

static void test_short_build_min(void) {
  const u8 dcid[1] = {0x99};
  u8       buf[8];
  usz      w = quic_short_build(buf, sizeof(buf), dcid, 1, 0, 0, 0x7F, 1);
  CHECK(w == 3);
  CHECK(buf[0] == 0x40); /* no spin, no key phase, pn_len 1 */
  CHECK(buf[1] == 0x99 && buf[2] == 0x7F);
}

static void test_short_bad_args(void) {
  const u8 dcid[4] = {0};
  u8       buf[16];
  CHECK(
      quic_short_build(buf, sizeof(buf), dcid, 4, 0, 0, 0, 0) ==
      0); /* pn_len 0 */
  CHECK(
      quic_short_build(buf, sizeof(buf), dcid, 4, 0, 0, 0, 5) ==
      0);                                                    /* pn_len 5 */
  CHECK(quic_short_build(buf, 3, dcid, 4, 0, 0, 0, 1) == 0); /* no room */
}

static void test_retry_roundtrip(void) {
  const u8 dcid[3]  = {0xD0, 0xD1, 0xD2};
  const u8 scid[2]  = {0x50, 0x51};
  const u8 token[5] = {0x10, 0x11, 0x12, 0x13, 0x14};
  u8       tag[QUIC_RETRY_TAG_LEN];
  for (usz i = 0; i < QUIC_RETRY_TAG_LEN; i++) tag[i] = (u8)(0xA0 + i);

  u8  buf[64];
  usz w =
      quic_retry_build(buf, sizeof(buf), 1, dcid, 3, scid, 2, token, 5, tag);
  CHECK(w == 5 + 1 + 3 + 1 + 2 + 5 + QUIC_RETRY_TAG_LEN);
  CHECK(buf[0] == 0xF0 && buf[4] == 1); /* type Retry, version 1 */

  quic_retry_packet r;
  usz               used = quic_retry_parse(buf, w, &r);
  CHECK(used == w);
  CHECK(r.version == 1 && r.dcid_len == 3 && r.scid_len == 2);
  CHECK(r.dcid[2] == 0xD2 && r.scid[0] == 0x50);
  CHECK(r.token_len == 5 && r.token[0] == 0x10 && r.token[4] == 0x14);
  CHECK(r.tag[0] == 0xA0 && r.tag[15] == 0xAF);
}

static void test_retry_truncated(void) {
  const u8 dcid[1]                 = {0x01};
  const u8 scid[1]                 = {0x02};
  const u8 token[1]                = {0x03};
  u8       tag[QUIC_RETRY_TAG_LEN] = {0};
  u8       buf[64];
  usz      w =
      quic_retry_build(buf, sizeof(buf), 1, dcid, 1, scid, 1, token, 1, tag);
  CHECK(w != 0);

  /* w - 1 still parses: the token is variable-length, so dropping a trailing
   * byte just yields a shorter (here zero-length) token. To force a failure
   * the buffer must be too small to even hold byte0..version + a CID + tag. */
  quic_retry_packet r;
  CHECK(quic_retry_parse(buf, 6, &r) == 0); /* too small for header + tag */
  CHECK(
      quic_retry_parse(buf, QUIC_RETRY_TAG_LEN + 6, &r) ==
      0); /* CID len overruns */
  CHECK(quic_retry_build(buf, 4, 1, dcid, 1, scid, 1, token, 1, tag) == 0);
}

static void test_vneg_roundtrip(void) {
  const u8  dcid[2] = {0xC0, 0xC1};
  const u8  scid[3] = {0x70, 0x71, 0x72};
  const u32 vers[2] = {0x00000001, 0x6B3343CF}; /* v1 and a GREASE-ish value */

  u8  buf[64];
  usz w = quic_vneg_build(buf, sizeof(buf), dcid, 2, scid, 3, vers, 2);
  CHECK(w == 5 + 1 + 2 + 1 + 3 + 2 * 4);
  CHECK(buf[0] == 0x80);
  CHECK(
      buf[1] == 0 && buf[2] == 0 && buf[3] == 0 && buf[4] == 0); /* Version 0 */

  quic_vneg_packet v;
  usz              used = quic_vneg_parse(buf, w, &v);
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
  usz       w =
      quic_vneg_respond(buf, sizeof(buf), recv_dcid, 2, recv_scid, 3, vers, 1);
  CHECK(w != 0);

  quic_vneg_packet v;
  CHECK(quic_vneg_parse(buf, w, &v) == w);
  /* response DCID is the received SCID; response SCID is the received DCID */
  CHECK(v.dcid_len == 3 && v.dcid[0] == 0x11 && v.dcid[2] == 0x33);
  CHECK(v.scid_len == 2 && v.scid[0] == 0xAA && v.scid[1] == 0xBB);
}

static void test_vneg_bad(void) {
  const u8  dcid[1] = {0x01};
  const u8  scid[1] = {0x02};
  const u32 vers[1] = {0x00000001};
  u8        buf[64];
  /* count 0 must fail to build */
  CHECK(quic_vneg_build(buf, sizeof(buf), dcid, 1, scid, 1, vers, 0) == 0);

  usz w = quic_vneg_build(buf, sizeof(buf), dcid, 1, scid, 1, vers, 1);
  CHECK(w != 0);
  buf[4] = 1; /* corrupt Version field to non-zero */
  quic_vneg_packet v;
  CHECK(quic_vneg_parse(buf, w, &v) == 0);
}

void test_packet2(void) {
  test_short_build();
  test_short_build_min();
  test_short_bad_args();
  test_retry_roundtrip();
  test_retry_truncated();
  test_vneg_roundtrip();
  test_vneg_respond_swap();
  test_vneg_bad();
}
