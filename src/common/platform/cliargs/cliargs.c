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
static int cli_streq(const char* a, const char* b) {
  usz i = 0;
  while (cli_char_match(a[i], b[i])) i++;
  return a[i] == b[i];
}

/* Index of argv[i] == flag with a following element, or -1 (none/dangling). */
static int cli_find(int argc, char** argv, const char* flag) {
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
static i64 cli_parse_u64(const char* s, int* ok) {
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

i64 wired_cliargs_int(int argc, char** argv, const char* flag, i64 defval) {
  int idx = cli_find(argc, argv, flag);
  i64 val;
  int ok;
  if (idx < 0) return defval;
  val = cli_parse_u64(argv[idx + 1], &ok);
  return ok ? val : defval;
}

const char* wired_cliargs_str(
    int argc, char** argv, const char* flag, const char* defval) {
  int idx = cli_find(argc, argv, flag);
  return idx < 0 ? defval : argv[idx + 1];
}

/* Index of argv[i] == flag over the FULL range (unlike cli_find, which
 * stops at argc-1 because it assumes a following value). Used by
 * wired_cliargs_flag, where flag may legally be argv's last element. */
static int cli_find_any(int argc, char** argv, const char* flag) {
  int i;
  for (i = 0; i < argc; i++) {
    if (cli_streq(argv[i], flag)) return i;
  }
  return -1;
}

int wired_cliargs_flag(int argc, char** argv, const char* flag) {
  return cli_find_any(argc, argv, flag) >= 0;
}

/* True if c is a base-10 digit; kept separate so its caller's while carries
 * only one condition (CCN budget, matches cli_char_match's pattern above). */
static int cli_is_digit(char c) { return c >= '0' && c <= '9'; }

/* Consume a run of digits at s[*i], accumulating into *val (no range check
 * here). Advances *i past the digits and returns the digit count (0 means
 * no digits were present). */
static usz ip_digits_read(const char* s, usz* i, i64* val) {
  i64 acc = 0;
  usz n   = 0;
  while (cli_is_digit(s[*i])) {
    acc = acc * 10 + (s[*i] - '0');
    (*i)++;
    n++;
  }
  *val = acc;
  return n;
}

/* An octet is invalid if it had no digits at all, or overflows a byte. */
static int ip_octet_invalid(usz ndigits, i64 val) {
  return ndigits == 0 || val > 255;
}

/* Parse one dotted-decimal octet at s[*i], requiring it be followed by
 * `want` ('.' for octets 0-2, NUL for the last). Advances *i past `want`
 * and stores the byte in *out on success. */
static int ip_octet_parse(const char* s, usz* i, char want, u8* out) {
  i64 val;
  usz n = ip_digits_read(s, i, &val);
  if (ip_octet_invalid(n, val)) return 0;
  if (s[*i] != want) return 0;
  *out = (u8)val;
  (*i)++;
  return 1;
}

/* Separator expected after octet idx: '.' for the first 3, NUL for the
 * last. Hoisted out so the caller's loop body carries only one branch. */
static char ip_octet_sep(int idx) {
  if (idx < 3) return '.';
  return 0;
}

int wired_cliargs_ipv4(const char* s, u8 out[4]) {
  u8  parsed[4];
  usz i = 0;
  int idx;
  for (idx = 0; idx < 4; idx++) {
    if (!ip_octet_parse(s, &i, ip_octet_sep(idx), &parsed[idx])) return 0;
  }
  out[0] = parsed[0];
  out[1] = parsed[1];
  out[2] = parsed[2];
  out[3] = parsed[3];
  return 1;
}
