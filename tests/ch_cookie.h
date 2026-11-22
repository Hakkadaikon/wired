#ifndef TESTS_CH_COOKIE_H
#define TESTS_CH_COOKIE_H

#include "common/bytes/util/be.h"
#include "tls/handshake/core/tls/handshake.h"

/* Test helper, RFC 8446 4.2.2: append a "cookie" extension carrying the
 * 16-byte ck to the ClientHello ch (n bytes, 4-byte handshake header),
 * patching the extensions and handshake lengths -- the echo a client owes a
 * HelloRetryRequest cookie. Returns the new length, 0 if cap is too small. */
static inline usz test_ch_add_cookie(u8* ch, usz n, usz cap, const u8* ck) {
  usz p = 4 + 2 + 32;
  if (n + 22 > cap) {
    return 0;
  }
  p += 1 + ch[p];               /* legacy_session_id */
  p += 2 + be_get_be16(ch + p); /* cipher_suites */
  p += 1 + ch[p];               /* legacy_compression_methods */
  be_put_be16(ch + n, 0x002c);  /* extension_type cookie */
  be_put_be16(ch + n + 2, 18);  /* extension_data length */
  be_put_be16(ch + n + 4, 16);  /* cookie<1..2^16-1> length */
  for (usz i = 0; i < 16; i++) {
    ch[n + 6 + i] = ck[i];
  }
  be_put_be16(ch + p, (u16)(be_get_be16(ch + p) + 22));
  hs_finish(ch, n + 22);
  return n + 22;
}

#endif
