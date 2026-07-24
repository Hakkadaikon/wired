#include "test.h"

/* All-lowercase field names are accepted. */
static void test_headercase_lower(void) {
  CHECK(quic_h3_header_name_ok((const u8*)"content-type", 12) == 1);
  CHECK(quic_h3_header_name_ok((const u8*)":path", 5) == 1);
  CHECK(quic_h3_header_name_ok((const u8*)"", 0) == 1);
}

/* Any uppercase letter makes the name malformed (H3_MESSAGE_ERROR). */
static void test_headercase_upper(void) {
  CHECK(quic_h3_header_name_ok((const u8*)"Content-Type", 12) == 0);
  CHECK(quic_h3_header_name_ok((const u8*)"hostX", 5) == 0);
  CHECK(quic_h3_header_name_ok((const u8*)"Authorization", 13) == 0);
}

/* Boundary bytes around A-Z stay allowed. */
static void test_headercase_boundary(void) {
  CHECK(quic_h3_header_name_ok((const u8*)"@[", 2) == 1); /* 0x40, 0x5b */
  CHECK(quic_h3_header_name_ok((const u8*)"a-z_0", 5) == 1);
}

/* Ordinary field names/values with no forbidden bytes are accepted. */
static void test_headerbytes_ok(void) {
  CHECK(quic_h3_header_bytes_ok((const u8*)"content-type", 12) == 1);
  CHECK(quic_h3_header_bytes_ok((const u8*)"text/plain", 10) == 1);
  CHECK(quic_h3_header_bytes_ok((const u8*)"", 0) == 1);
}

/* A CR (0x0d) anywhere in the buffer is malformed (H3_MESSAGE_ERROR). */
static void test_headerbytes_cr(void) {
  CHECK(quic_h3_header_bytes_ok((const u8*)"foo\rbar", 7) == 0);
  CHECK(quic_h3_header_bytes_ok((const u8*)"\r", 1) == 0);
}

/* A LF (0x0a) anywhere in the buffer is malformed (H3_MESSAGE_ERROR). */
static void test_headerbytes_lf(void) {
  CHECK(quic_h3_header_bytes_ok((const u8*)"foo\nbar", 7) == 0);
  CHECK(quic_h3_header_bytes_ok((const u8*)"\n", 1) == 0);
}

/* A NUL (0x00) anywhere in the buffer is malformed (H3_MESSAGE_ERROR). */
static void test_headerbytes_nul(void) {
  u8 buf[] = {'f', 'o', 'o', 0x00, 'b', 'a', 'r'};
  CHECK(quic_h3_header_bytes_ok(buf, sizeof buf) == 0);
  u8 nul = 0x00;
  CHECK(quic_h3_header_bytes_ok(&nul, 1) == 0);
}

void test_headercase(void) {
  test_headercase_lower();
  test_headercase_upper();
  test_headercase_boundary();
  test_headerbytes_ok();
  test_headerbytes_cr();
  test_headerbytes_lf();
  test_headerbytes_nul();
}
