#include "tls/keys/keyupdate/kuderive.h"

#include "common/bytes/util/bytes.h"
#include "crypto/kdf/hkdf/hkdf.h"
#include "transport/version/version/v2keys.h"
#include "transport/version/version/version.h"

/* RFC 9001 6.1 / RFC 9369 3.3.2: the "ku" label is the version's
 * HKDF-Expand-Label prefix ("quic "/"quicv2 ") with "ku" appended --
 * "quic "+"ku"="quic ku" (7 bytes), "quicv2 "+"ku"="quicv2 ku" (9 bytes). */
#define KU_LABEL_MAX 9

static usz ku_label_build(u8 buf[KU_LABEL_MAX], u32 version) {
  const char* prefix;
  usz         prefix_len;
  if (!quic_version_label_prefix(version, &prefix, &prefix_len))
    quic_version_label_prefix(QUIC_VERSION_1, &prefix, &prefix_len);
  quic_memcpy(buf, prefix, prefix_len);
  buf[prefix_len]     = 'k';
  buf[prefix_len + 1] = 'u';
  return prefix_len + 2;
}

void quic_ku_next_secret_v(u32 version, const u8 cur[32], u8 next[32]) {
  u8              buf[KU_LABEL_MAX];
  usz             n = ku_label_build(buf, version);
  quic_hkdf_label l = {(const char*)buf, n, {0, 0}};
  quic_hkdf_expand_label(cur, &l, quic_mspan_of(next, 32));
}

void quic_ku_next_secret(const u8 cur[32], u8 next[32]) {
  quic_ku_next_secret_v(QUIC_VERSION_1, cur, next);
}
