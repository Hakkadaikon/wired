#ifndef TESTS_EE_FIND_H
#define TESTS_EE_FIND_H

#include "common/bytes/span/span.h"

/* Test helper: the extension_data of extension `type` inside the
 * EncryptedExtensions message at ee (4-byte handshake header, then
 * extensions<2>, RFC 8446 4.3.1). Returns 1 and sets *data when found. */
static inline int ee_find(const u8* ee, unsigned type, wired_span* data) {
  usz end = 6 + ((usz)ee[4] << 8 | ee[5]);
  for (usz q = 6; q + 4 <= end;) {
    unsigned t = (unsigned)ee[q] << 8 | ee[q + 1];
    usz      n = (usz)ee[q + 2] << 8 | ee[q + 3];
    if (t == type) {
      *data = wired_span_of(ee + q + 4, n);
      return 1;
    }
    q += 4 + n;
  }
  return 0;
}

#endif
