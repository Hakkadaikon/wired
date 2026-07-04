#include "tls/ext/alpnver/alpnver.h"

#include "tls/handshake/core/tls/alpn_match.h"
#include "transport/version/version/compat.h"

/* RFC 9001 8.1: an ALPN protocol must be selected for a QUIC handshake. */
int quic_alpnver_require(const u8* selected_alpn, usz len) {
  return selected_alpn != 0 && len > 0;
}

/* RFC 7301 3.2 / RFC 9114: classify the selected name. */
quic_alpnver_proto quic_alpnver_protocol(const u8* alpn, usz len) {
  if (quic_tls_alpn_is_h3(alpn, len)) return QUIC_ALPNVER_PROTO_H3;
  return QUIC_ALPNVER_PROTO_NONE;
}

/* RFC 9368 / RFC 9000 7.4: known protocol stays valid across compatible
 * versions. quic_version_compatible(v, v) is true only for known versions. */
int quic_alpnver_compatible(u32 version, const u8* alpn, usz len) {
  if (quic_alpnver_protocol(alpn, len) == QUIC_ALPNVER_PROTO_NONE) return 0;
  return quic_version_compatible(version, version);
}
