#ifndef QUIC_QPACKDYN_CSTR_H
#define QUIC_QPACKDYN_CSTR_H

#include "common/platform/sys/syscall.h"

/* Length of a NUL-terminated string (static-table names/values are C strings).
 * Inline to avoid a libc strlen dependency. */
static inline usz quic_qdyn_cstr_len(const char *s) {
  usz n = 0;
  while (s[n]) n++;
  return n;
}

#endif
