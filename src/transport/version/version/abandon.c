#include "transport/version/version/abandon.h"

/* RFC 9368 3 */
static int supported(const u32* we_support, usz n_support, u32 v) {
  for (usz i = 0; i < n_support; i++)
    if (we_support[i] == v) return 1;
  return 0;
}

/* RFC 9368 3: a usable offered version is non-reserved and supported. */
static int usable(u32 v, const u32* we_support, usz n_support) {
  return !quic_version_is_reserved(v) && supported(we_support, n_support, v);
}

/* RFC 9368 3 */
int quic_version_must_abandon(quic_verlist offered, quic_verlist we_support) {
  for (usz i = 0; i < offered.n; i++)
    if (usable(offered.list[i], we_support.list, we_support.n)) return 0;
  return 1;
}
