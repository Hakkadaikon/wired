#include "common/platform/envp/envp.h"

/* Name char still to consume and matching the entry char. */
static int env_char_match(char n, char c) { return n && n == c; }

/* Name fully consumed exactly at the '=' separator. */
static int env_at_sep(char n, char c) { return n == 0 && c == '='; }

/* If s is "name=value", return a pointer to value; otherwise 0. */
static const char* env_match(const char* s, const char* name) {
  usz i = 0;
  while (env_char_match(name[i], s[i])) i++;
  return env_at_sep(name[i], s[i]) ? s + i + 1 : 0;
}

const char* wired_envp_get(int argc, char** argv, const char* name) {
  char** env = argv + argc + 1;
  usz    i;
  for (i = 0; env[i]; i++) {
    const char* v = env_match(env[i], name);
    if (v) return v;
  }
  return 0;
}
