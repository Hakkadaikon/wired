#include "common/platform/cliargs/cliargs.h"

/* NOTE on scope: this file only parses an argc/argv already materialized as
 * pointers (a test double array, or a real argv handed down by whatever
 * built it). It deliberately does NOT read the raw kernel stack that a
 * freestanding _start sees on entry (argc/argv/envp packed above RSP, see
 * the task description). That extraction needs an asm shim and a change to
 * _start's signature in examples/word_list/wired_server.c, which is a
 * different task's file — left undone here on purpose, see the task report.
 * The logic below is the testable half: flag lookup + integer parsing. */

/* Both chars nonzero and equal: the "still matching" predicate lives here so
 * cli_streq's while carries only one condition (CCN budget, see the repo's
 * ccn-and-complexity rule). */
static int cli_char_match(char a, char b) { return a && b && a == b; }

/* NUL-terminated ascii compare, no libc strcmp available. */
static int cli_streq(const char *a, const char *b) {
  usz i = 0;
  while (cli_char_match(a[i], b[i])) i++;
  return a[i] == b[i];
}

/* Index of argv[i] == flag with a following element, or -1 (none/dangling). */
static int cli_find(int argc, char **argv, const char *flag) {
  int i;
  for (i = 0; i < argc - 1; i++) {
    if (cli_streq(argv[i], flag)) return i;
  }
  return -1;
}

/* One base-10 digit accumulate step; -1 signals "not a digit". */
static i64 cli_digit_step(i64 acc, char c) {
  if (c < '0' || c > '9') return -1;
  return acc * 10 + (c - '0');
}

/* Parse s as a non-negative base-10 integer; ok is set 0 on any non-digit
 * or an empty string. */
static i64 cli_parse_u64(const char *s, int *ok) {
  i64 acc = 0;
  usz i;
  *ok = s[0] != 0;
  for (i = 0; s[i]; i++) {
    acc = cli_digit_step(acc, s[i]);
    if (acc < 0) {
      *ok = 0;
      return 0;
    }
  }
  return acc;
}

i64 wired_cliargs_int(int argc, char **argv, const char *flag, i64 defval) {
  int idx = cli_find(argc, argv, flag);
  i64 val;
  int ok;
  if (idx < 0) return defval;
  val = cli_parse_u64(argv[idx + 1], &ok);
  return ok ? val : defval;
}

const char *wired_cliargs_str(
    int argc, char **argv, const char *flag, const char *defval) {
  int idx = cli_find(argc, argv, flag);
  return idx < 0 ? defval : argv[idx + 1];
}
