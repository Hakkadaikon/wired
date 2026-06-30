#include "transport/version/version/switchrule.h"

#include "transport/version/version/compat.h"

/* RFC 9369 4.1 */
int quic_version_retry_reencode(u32 from, u32 to) { return from != to; }

/* RFC 9369 4.1 */
int quic_version_0rtt_keep(u32 original, u32 negotiated) {
  if (original == negotiated) return 1;
  return quic_version_compatible(original, negotiated);
}
