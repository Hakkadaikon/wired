#include "app/http3/server/hq09/hq09.h"

#include "test.h"

/* A well-formed "GET <path>\r\n" line yields <path> exactly. */
static void test_hq09_parse_get_request_extracts_path(void) {
  static const u8 line[] = "GET /file1.txt\r\n";
  quic_span       path;
  CHECK(wired_hq09_parse_get(quic_span_of(line, sizeof(line) - 1), &path));
  CHECK(path.n == 10);
  CHECK(path.p[0] == '/' && path.p[1] == 'f' && path.p[9] == 't');
}

/* A line ending in bare "\n" (no "\r") is tolerated the same way,
 * matching the reference server's TrimRight("\r\n") which strips either
 * character independently. */
static void test_hq09_parse_get_request_tolerates_lf_only(void) {
  static const u8 line[] = "GET /file1.txt\n";
  quic_span       path;
  CHECK(wired_hq09_parse_get(quic_span_of(line, sizeof(line) - 1), &path));
  CHECK(path.n == 10);
}

/* A line with no trailing newline at all (the client closed the stream
 * right after the bytes, no framing byte) still parses -- the newline is
 * optional punctuation this parser tolerates, not a required delimiter. */
static void test_hq09_parse_get_request_tolerates_no_newline(void) {
  static const u8 line[] = "GET /file1.txt";
  quic_span       path;
  CHECK(wired_hq09_parse_get(quic_span_of(line, sizeof(line) - 1), &path));
  CHECK(path.n == 10);
}

/* Neither a non-GET method nor a path missing its leading "/" is
 * accepted. */
static void test_hq09_parse_get_request_rejects_non_get_or_no_slash(void) {
  static const u8 not_get[]   = "PUT /file1.txt\r\n";
  static const u8 no_slash[]  = "GET file1.txt\r\n";
  static const u8 too_short[] = "GE";
  quic_span       path;
  CHECK(
      !wired_hq09_parse_get(quic_span_of(not_get, sizeof(not_get) - 1), &path));
  CHECK(!wired_hq09_parse_get(
      quic_span_of(no_slash, sizeof(no_slash) - 1), &path));
  CHECK(!wired_hq09_parse_get(
      quic_span_of(too_short, sizeof(too_short) - 1), &path));
}

/* Boundary: the bare root path "/" (list of length 1) still parses to an
 * empty-after-slash-inclusive path, not rejected as too short. */
static void test_hq09_parse_get_request_root_path(void) {
  static const u8 line[] = "GET /\r\n";
  quic_span       path;
  CHECK(wired_hq09_parse_get(quic_span_of(line, sizeof(line) - 1), &path));
  CHECK(path.n == 1);
  CHECK(path.p[0] == '/');
}

static void test_hq09(void) {
  test_hq09_parse_get_request_extracts_path();
  test_hq09_parse_get_request_tolerates_lf_only();
  test_hq09_parse_get_request_tolerates_no_newline();
  test_hq09_parse_get_request_rejects_non_get_or_no_slash();
  test_hq09_parse_get_request_root_path();
}
