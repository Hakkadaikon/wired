#include "test.h"

/* wired_cliargs_{int,str} parse already-materialized argc/argv (test double
 * arrays here; the real argv comes from _start's stack layout — see
 * cliargs.c's file comment for why that part is not unit-tested). */

/* --port 8080: flag present with a numeric value returns the parsed int. */
static void test_cliargs_int_found(void) {
  char* argv[] = {"prog", "--port", "8080"};
  CHECK(wired_cliargs_int(3, argv, "--port", 4433) == 8080);
}

/* Flag absent: falls back to the caller-supplied default. */
static void test_cliargs_int_missing(void) {
  char* argv[] = {"prog"};
  CHECK(wired_cliargs_int(1, argv, "--port", 4433) == 4433);
}

/* Flag present but the value is not numeric: default wins (safe fallback). */
static void test_cliargs_int_not_numeric(void) {
  char* argv[] = {"prog", "--port", "abc"};
  CHECK(wired_cliargs_int(3, argv, "--port", 4433) == 4433);
}

/* Flag is the last argv element, no value follows: default wins. */
static void test_cliargs_int_dangling(void) {
  char* argv[] = {"prog", "--port"};
  CHECK(wired_cliargs_int(2, argv, "--port", 4433) == 4433);
}

/* Flag found among others: search doesn't stop at the first argv entry. */
static void test_cliargs_str_found(void) {
  char*       argv[] = {"prog", "--port", "8080", "--cert", "cert.pem"};
  const char* v      = wired_cliargs_str(5, argv, "--cert", 0);
  CHECK(v != 0);
  CHECK(v[0] == 'c' && v[1] == 'e' && v[2] == 'r' && v[3] == 't');
}

/* Flag absent: returns the caller-supplied default (0/NULL here). */
static void test_cliargs_str_missing(void) {
  char* argv[] = {"prog"};
  CHECK(wired_cliargs_str(1, argv, "--cert", 0) == 0);
}

/* wired_cliargs_flag test list:
 * - flag present in the middle of argv -> 1
 * - flag is the last argv element (boundary cli_find can't see) -> 1
 * - flag absent -> 0
 * - empty argv (argc == 0) -> 0
 * - argc == 1 (program name only) -> 0
 * - a different flag that is a prefix/superset ("--core" vs "--cores")
 *   does not false-match either direction
 */

/* Flag present among others, not at argv end: found. */
static void test_cliargs_flag_found_middle(void) {
  char* argv[] = {"prog", "--verbose", "--port", "8080"};
  CHECK(wired_cliargs_flag(4, argv, "--verbose") == 1);
}

/* Flag is argv's last element: cli_find (argc-1 bound) would miss this,
 * so flag lookup needs its own full-argc scan. */
static void test_cliargs_flag_found_at_end(void) {
  char* argv[] = {"prog", "--port", "8080", "--verbose"};
  CHECK(wired_cliargs_flag(4, argv, "--verbose") == 1);
}

/* Flag never appears: not found. */
static void test_cliargs_flag_not_found(void) {
  char* argv[] = {"prog", "--port", "8080"};
  CHECK(wired_cliargs_flag(3, argv, "--verbose") == 0);
}

/* Empty argv: no crash, not found. */
static void test_cliargs_flag_empty_argv(void) {
  char* argv[] = {0};
  CHECK(wired_cliargs_flag(0, argv, "--verbose") == 0);
}

/* Only the program name: not found. */
static void test_cliargs_flag_argc_one(void) {
  char* argv[] = {"prog"};
  CHECK(wired_cliargs_flag(1, argv, "--verbose") == 0);
}

/* "--cores" present must not false-match a search for "--core", and vice
 * versa: prefix/superset flags must not be confused. */
static void test_cliargs_flag_no_prefix_confusion(void) {
  char* argv[] = {"prog", "--cores", "4"};
  CHECK(wired_cliargs_flag(3, argv, "--core") == 0);
}

/* wired_cliargs_ipv4 test list:
 * - "127.0.0.1", "0.0.0.0", "255.255.255.255" -> 1, correct bytes
 * - "256.0.0.0" (octet out of range) -> 0
 * - "1.2.3.4.5" (too many segments) -> 0
 * - "1.2.3" (too few segments) -> 0
 * - "1..3.4" (empty segment) -> 0
 * - "1.2.3.a" (non-digit) -> 0
 * - "1.2.3.4x" (trailing garbage) -> 0
 * - "" (empty string) -> 0
 */

/* Loopback address parses to {127,0,0,1}. */
static void test_cliargs_ipv4_loopback(void) {
  u8 out[4] = {9, 9, 9, 9};
  CHECK(wired_cliargs_ipv4("127.0.0.1", out) == 1);
  CHECK(out[0] == 127 && out[1] == 0 && out[2] == 0 && out[3] == 1);
}

/* All-zero address. */
static void test_cliargs_ipv4_all_zero(void) {
  u8 out[4] = {9, 9, 9, 9};
  CHECK(wired_cliargs_ipv4("0.0.0.0", out) == 1);
  CHECK(out[0] == 0 && out[1] == 0 && out[2] == 0 && out[3] == 0);
}

/* Max octet value in every position. */
static void test_cliargs_ipv4_max(void) {
  u8 out[4] = {0, 0, 0, 0};
  CHECK(wired_cliargs_ipv4("255.255.255.255", out) == 1);
  CHECK(out[0] == 255 && out[1] == 255 && out[2] == 255 && out[3] == 255);
}

/* Octet exceeds 255: rejected. */
static void test_cliargs_ipv4_octet_overflow(void) {
  u8 out[4] = {9, 9, 9, 9};
  CHECK(wired_cliargs_ipv4("256.0.0.0", out) == 0);
}

/* Too many segments: rejected. */
static void test_cliargs_ipv4_too_many_segments(void) {
  u8 out[4] = {9, 9, 9, 9};
  CHECK(wired_cliargs_ipv4("1.2.3.4.5", out) == 0);
}

/* Too few segments: rejected. */
static void test_cliargs_ipv4_too_few_segments(void) {
  u8 out[4] = {9, 9, 9, 9};
  CHECK(wired_cliargs_ipv4("1.2.3", out) == 0);
}

/* Empty segment between dots: rejected. */
static void test_cliargs_ipv4_empty_segment(void) {
  u8 out[4] = {9, 9, 9, 9};
  CHECK(wired_cliargs_ipv4("1..3.4", out) == 0);
}

/* Non-digit character in a segment: rejected. */
static void test_cliargs_ipv4_non_digit(void) {
  u8 out[4] = {9, 9, 9, 9};
  CHECK(wired_cliargs_ipv4("1.2.3.a", out) == 0);
}

/* Trailing garbage after the last octet: rejected. */
static void test_cliargs_ipv4_trailing_garbage(void) {
  u8 out[4] = {9, 9, 9, 9};
  CHECK(wired_cliargs_ipv4("1.2.3.4x", out) == 0);
}

/* Empty string: rejected. */
static void test_cliargs_ipv4_empty_string(void) {
  u8 out[4] = {9, 9, 9, 9};
  CHECK(wired_cliargs_ipv4("", out) == 0);
}

void test_cliargs(void) {
  test_cliargs_int_found();
  test_cliargs_int_missing();
  test_cliargs_int_not_numeric();
  test_cliargs_int_dangling();
  test_cliargs_str_found();
  test_cliargs_str_missing();
  test_cliargs_flag_found_middle();
  test_cliargs_flag_found_at_end();
  test_cliargs_flag_not_found();
  test_cliargs_flag_empty_argv();
  test_cliargs_flag_argc_one();
  test_cliargs_flag_no_prefix_confusion();
  test_cliargs_ipv4_loopback();
  test_cliargs_ipv4_all_zero();
  test_cliargs_ipv4_max();
  test_cliargs_ipv4_octet_overflow();
  test_cliargs_ipv4_too_many_segments();
  test_cliargs_ipv4_too_few_segments();
  test_cliargs_ipv4_empty_segment();
  test_cliargs_ipv4_non_digit();
  test_cliargs_ipv4_trailing_garbage();
  test_cliargs_ipv4_empty_string();
}
