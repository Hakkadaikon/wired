#include "test.h"

/* wired_envp_get scans the environ block the Linux ABI places right after
 * argv (argv + argc + 1, NULL-terminated). Tests rebuild that layout as a
 * plain pointer array: argv[argc] = NULL, then env strings, then NULL. */

/* Variable present: returns the value after '='. */
static void test_envp_get_found(void) {
  char*       argv[] = {"prog", 0, "PROTOCOLS=h3", 0};
  const char* v      = wired_envp_get(1, argv, "PROTOCOLS");
  CHECK(v != 0);
  CHECK(v[0] == 'h');
  CHECK(v[1] == '3');
  CHECK(v[2] == 0);
}

/* Variable absent: returns 0. */
static void test_envp_get_missing(void) {
  char* argv[] = {"prog", 0, "OTHER=1", 0};
  CHECK(wired_envp_get(1, argv, "PROTOCOLS") == 0);
}

/* Empty value ("FOO="): returns the empty string, not 0. */
static void test_envp_get_empty_value(void) {
  char*       argv[] = {"prog", 0, "FOO=", 0};
  const char* v      = wired_envp_get(1, argv, "FOO");
  CHECK(v != 0);
  CHECK(v[0] == 0);
}

/* "FOO" must not match "FOOBAR=x" (prefix confusion). */
static void test_envp_get_no_prefix_confusion(void) {
  char* argv[] = {"prog", 0, "FOOBAR=x", 0};
  CHECK(wired_envp_get(1, argv, "FOO") == 0);
}

/* Name longer than the env entry's name must not match either. */
static void test_envp_get_name_longer(void) {
  char* argv[] = {"prog", 0, "FO=x", 0};
  CHECK(wired_envp_get(1, argv, "FOO") == 0);
}

/* Empty environ block (NULL right after argv's NULL): returns 0. */
static void test_envp_get_empty_environ(void) {
  char* argv[] = {"prog", 0, 0};
  CHECK(wired_envp_get(1, argv, "PROTOCOLS") == 0);
}

/* Picks the right entry among several. */
static void test_envp_get_among_many(void) {
  char*       argv[] = {"prog", "arg1", 0, "A=1", "PROTOCOLS=h3,h2", "Z=9", 0};
  const char* v      = wired_envp_get(2, argv, "PROTOCOLS");
  CHECK(v != 0);
  CHECK(v[0] == 'h');
  CHECK(v[1] == '3');
  CHECK(v[2] == ',');
}

void test_envp(void) {
  test_envp_get_found();
  test_envp_get_missing();
  test_envp_get_empty_value();
  test_envp_get_no_prefix_confusion();
  test_envp_get_name_longer();
  test_envp_get_empty_environ();
  test_envp_get_among_many();
}
