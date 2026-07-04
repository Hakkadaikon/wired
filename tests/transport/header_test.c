#include "test.h"

/* RFC 9000 17.2: long header byte0 has high bit + fixed bit set (0xC0),
 * type in bits 5-4, then 4-byte version and two length-prefixed CIDs. */
static void test_header_parse_long(void) {
  /* Initial: byte0=0xC0, version=1, DCID len 4, SCID len 0. */
  const u8     pkt[] = {0xC0, 0, 0, 0, 1, 4, 0xDE, 0xAD, 0xBE, 0xEF, 0};
  wired_header h;
  usz          used = wired_header_parse(pkt, sizeof(pkt), &h);
  CHECK(used == sizeof(pkt));
  CHECK(h.form == WIRED_FORM_LONG && h.long_type == WIRED_LP_INITIAL);
  CHECK(h.version == 1 && h.dcid_len == 4 && h.scid_len == 0);
  CHECK(h.dcid[0] == 0xDE && h.dcid[3] == 0xEF);
}

static void test_header_parse_short(void) {
  const u8 pkt[] = {0x40, 0x11, 0x22, 0x33, 0x44}; /* short form, DCID len 4 */
  wired_header h;
  h.dcid_len = 4; /* caller's known local CID length */
  usz used   = wired_header_parse(pkt, sizeof(pkt), &h);
  CHECK(used == 5 && h.form == WIRED_FORM_SHORT && h.dcid[0] == 0x11);
}

static void test_header_build_roundtrip(void) {
  wired_header in = {0};
  in.long_type    = WIRED_LP_HANDSHAKE;
  in.version      = 1;
  in.dcid_len     = 4;
  in.dcid[0]      = 0xDE;
  in.dcid[1]      = 0xAD;
  in.dcid[2]      = 0xBE;
  in.dcid[3]      = 0xEF;
  in.scid_len     = 2;
  in.scid[0]      = 0xAB;
  in.scid[1]      = 0xCD;

  u8  buf[64];
  usz w = wired_header_build_long(buf, sizeof(buf), &in);
  CHECK(w == 5 + 1 + 4 + 1 + 2);

  wired_header out;
  usz          r = wired_header_parse(buf, w, &out);
  CHECK(r == w && out.long_type == WIRED_LP_HANDSHAKE && out.version == 1);
  CHECK(out.dcid_len == 4 && out.dcid[3] == 0xEF);
  CHECK(out.scid_len == 2 && out.scid[1] == 0xCD);
}

static void test_header_truncated(void) {
  wired_header h;
  CHECK(wired_header_parse((const u8*)"", 0, &h) == 0);
  /* claims DCID len 4 but only 2 bytes follow */
  const u8 bad[] = {0xC0, 0, 0, 0, 1, 4, 0xDE, 0xAD};
  CHECK(wired_header_parse(bad, sizeof(bad), &h) == 0);
  /* build into too-small buffer */
  u8 small[4];
  CHECK(wired_header_build_long(small, sizeof(small), &h) == 0);
}

/* Fuzz-found (2026-07-04): a long-header byte0 with fewer than 5 bytes
 * total must not read past the buffer while pulling the 4-byte version. */
static void test_header_long_too_short_for_version(void) {
  wired_header h;
  const u8     one[] = {0xCA};
  CHECK(wired_header_parse(one, sizeof(one), &h) == 0);
  const u8 two[] = {0xCA, 0x2F};
  CHECK(wired_header_parse(two, sizeof(two), &h) == 0);
  const u8 four[] = {0xCA, 0, 0, 0};
  CHECK(wired_header_parse(four, sizeof(four), &h) == 0);
}

void test_header(void) {
  test_header_parse_long();
  test_header_parse_short();
  test_header_build_roundtrip();
  test_header_truncated();
  test_header_long_too_short_for_version();
}
