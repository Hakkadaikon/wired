#include "tls/keys/keyupdate/aeadlimit.h"

int aead_needs_update(u64 packets_encrypted, int is_chacha) {
  /* RFC 9001 6.6 */
  u64 limit = is_chacha ? AEAD_LIMIT_CHACHA : AEAD_LIMIT_AESGCM;
  return packets_encrypted >= limit;
}
