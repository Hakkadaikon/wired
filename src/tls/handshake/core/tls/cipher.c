#include "tls/handshake/core/tls/cipher.h"

/* RFC 8446 B.4 server preference: lower is preferred, 0 = unsupported. */
static int cipher_rank(u16 suite) {
  static const u16 pref[] = {
      TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
      TLS_AES_256_GCM_SHA384};
  for (usz i = 0; i < sizeof pref / sizeof *pref; i++)
    if (pref[i] == suite) return (int)i + 1;
  return 0;
}

int cipher_supported(u16 suite) { return cipher_rank(suite) != 0; }

/* Whether s should replace the current pick: the first supported one, or a
 * better-ranked one. */
static int prefer(u16 s, u16 chosen, int found) {
  return !found || cipher_rank(s) < cipher_rank(chosen);
}

static void fold(u16 s, u16* chosen, int* found) {
  if (!cipher_supported(s)) return;
  if (prefer(s, *chosen, *found)) *chosen = s;
  *found = 1;
}

int cipher_select(const u8* offered, usz n_pairs, u16* chosen) {
  int found = 0;
  for (usz i = 0; i < n_pairs; i++)
    fold((u16)((offered[2 * i] << 8) | offered[2 * i + 1]), chosen, &found);
  return found;
}
