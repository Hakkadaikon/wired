#include "tls/keys/keyupdate/aeadintegrity.h"

int quic_aead_integrity_exceeded(u64 auth_failures, int is_chacha) {
  /* RFC 9001 6.6 */
  u64 limit = is_chacha ? QUIC_AEAD_INTEGRITY_LIMIT_CHACHA
                        : QUIC_AEAD_INTEGRITY_LIMIT_AESGCM;
  return auth_failures >= limit;
}
