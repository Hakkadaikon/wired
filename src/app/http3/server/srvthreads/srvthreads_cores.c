#include "app/http3/server/srvthreads/srvthreads_impl.h"

static int srvthreads_cores_more_field(char c);
static int srvthreads_cores_digit(int acc, char c);
static usz srvthreads_cores_consume(const char* s, usz* off, int* acc);
static int srvthreads_cores_parse_one(const char* s, usz* off, int* out);
static int srvthreads_cores_parse_more(const char* s, usz* off);
static int srvthreads_cores_parse_field(
    const char* s, usz* off, int* cores, int n, int cap);
static int srvthreads_cores_parse_done(const char* s, usz off, int n);
static int srvthreads_cores_parse_all(const char* s, int* cores, int cap);

/* --- --cores a,b,c parsing (example servers each reimplemented this;
 * pulled into the SDK) -------
 * Same "one digit accumulate, -1 signals not-a-digit" shape as cliargs.c's
 * cli_digit_step, kept local since a core list is a srvthreads-only
 * concept. */

/* Non-comma, non-NUL: a field continues over exactly these bytes, so the
 * digit loop below carries only this one predicate call instead of a
 * two-part && condition (CCN budget). */
static int srvthreads_cores_more_field(char c) { return c && c != ','; }

/* One base-10 digit accumulate step; -1 signals "not a digit". */
static int srvthreads_cores_digit(int acc, char c) {
  if (c < '0' || c > '9') return -1;
  return acc * 10 + (c - '0');
}

/* Consume base-10 digits from s[*off..) up to ',' or NUL, folding them into
 * *acc via srvthreads_cores_digit. Returns the digit count consumed; *acc
 * is only meaningful when the count is nonzero and no non-digit was seen
 * (caller's job to check). */
static usz srvthreads_cores_consume(const char* s, usz* off, int* acc) {
  usz digits = 0;
  *acc       = 0;
  while (srvthreads_cores_more_field(s[*off])) {
    *acc = srvthreads_cores_digit(*acc, s[*off]);
    if (*acc < 0) return 0;
    digits++;
    (*off)++;
  }
  return digits;
}

/* One field parsed from s[*off..), stopping at ',' or the terminating NUL.
 * Returns 1 ok (an int core index written to *out, *off advanced past the
 * field), 0 if the field is empty or contains a non-digit -- both make the
 * field itself malformed. */
static int srvthreads_cores_parse_one(const char* s, usz* off, int* out) {
  int acc;
  usz digits = srvthreads_cores_consume(s, off, &acc);
  if (!digits) return 0;
  *out = acc;
  return 1;
}

/* 1 and advances *off past a ',' when one follows (more fields to parse); 0
 * with *off left at the NUL when the list ends here. */
static int srvthreads_cores_parse_more(const char* s, usz* off) {
  if (s[*off] != ',') return 0;
  (*off)++;
  return 1;
}

/* Parse field index n (n < cap already checked by the caller) into
 * cores[n] and advance *off past it. Returns 1 ok, 0 malformed. */
static int srvthreads_cores_parse_field(
    const char* s, usz* off, int* cores, int n, int cap) {
  if (n >= cap) return 0;
  return srvthreads_cores_parse_one(s, off, &cores[n]);
}

/* n if the list ended right here (NUL), -1 if srvthreads_cores_parse_more
 * said "no more" but trailing garbage remains. */
static int srvthreads_cores_parse_done(const char* s, usz off, int n) {
  return s[off] == 0 ? n : -1;
}

/* Parse every field into cores[0..cap), stopping at the first malformed
 * field, a field beyond cap, or the end of the list. Returns the field
 * count on a clean end-of-string, -1 on any malformed field or overflow. */
static int srvthreads_cores_parse_all(const char* s, int* cores, int cap) {
  usz off = 0;
  int n   = 0;
  while (srvthreads_cores_parse_field(s, &off, cores, n, cap)) {
    n++;
    if (!srvthreads_cores_parse_more(s, &off))
      return srvthreads_cores_parse_done(s, off, n);
  }
  return -1;
}

int wired_srvthreads_parse_cores(const char* s, wired_srvthreads_opt* opt) {
  int cores[WIRED_SRVTHREADS_MAX];
  int n = srvthreads_cores_parse_all(s, cores, (int)WIRED_SRVTHREADS_MAX);
  if (n < 0) return 0;
  for (int i = 0; i < n; i++) opt->cores[i] = cores[i];
  opt->n_cores = n;
  return 1;
}
