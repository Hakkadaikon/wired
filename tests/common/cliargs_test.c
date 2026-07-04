#include "test.h"

/* wired_cliargs_{int,str} parse already-materialized argc/argv (test double
 * arrays here; the real argv comes from _start's stack layout — see
 * cliargs.c's file comment for why that part is not unit-tested). */

/* --port 8080: flag present with a numeric value returns the parsed int. */
static void test_cliargs_int_found(void) {
  char *argv[] = {"prog", "--port", "8080"};
  CHECK(wired_cliargs_int(3, argv, "--port", 4433) == 8080);
}

/* Flag absent: falls back to the caller-supplied default. */
static void test_cliargs_int_missing(void) {
  char *argv[] = {"prog"};
  CHECK(wired_cliargs_int(1, argv, "--port", 4433) == 4433);
}

/* Flag present but the value is not numeric: default wins (safe fallback). */
static void test_cliargs_int_not_numeric(void) {
  char *argv[] = {"prog", "--port", "abc"};
  CHECK(wired_cliargs_int(3, argv, "--port", 4433) == 4433);
}

/* Flag is the last argv element, no value follows: default wins. */
static void test_cliargs_int_dangling(void) {
  char *argv[] = {"prog", "--port"};
  CHECK(wired_cliargs_int(2, argv, "--port", 4433) == 4433);
}

/* Flag found among others: search doesn't stop at the first argv entry. */
static void test_cliargs_str_found(void) {
  char *argv[] = {"prog", "--port", "8080", "--cert", "cert.pem"};
  const char *v = wired_cliargs_str(5, argv, "--cert", 0);
  CHECK(v != 0);
  CHECK(v[0] == 'c' && v[1] == 'e' && v[2] == 'r' && v[3] == 't');
}

/* Flag absent: returns the caller-supplied default (0/NULL here). */
static void test_cliargs_str_missing(void) {
  char *argv[] = {"prog"};
  CHECK(wired_cliargs_str(1, argv, "--cert", 0) == 0);
}

void test_cliargs(void) {
  test_cliargs_int_found();
  test_cliargs_int_missing();
  test_cliargs_int_not_numeric();
  test_cliargs_int_dangling();
  test_cliargs_str_found();
  test_cliargs_str_missing();
}
