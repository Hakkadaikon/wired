#include "tls/keys/keyupdate/kuderive.h"

#include "crypto/kdf/hkdf/hkdf.h"

void quic_ku_next_secret(const u8 cur[32], u8 next[32]) {
  /* RFC 9001 6.1 */
  quic_hkdf_label l = {"quic ku", 7, {0, 0}};
  quic_hkdf_expand_label(cur, &l, quic_mspan_of(next, 32));
}
