#include "transport/conn/loop/connrunner/level.h"

#include "crypto/kdf/keys/keyset.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/version/version/version.h"

/* Version 0 is every pre-existing caller (written before the parameter
 * existed) -- treat it as the QUIC v1 they all meant. */
static u32 level_version_or_v1(u32 v) { return v ? v : VERSION_1; }

/* RFC 9000 17.2 (v1) / RFC 9369 3.2 (v2): a long-header Initial or Handshake
 * type maps to its keyset level; 0-RTT and Retry are not driven by this
 * loop. The type-bit layout follows the connection's negotiated version. */
static int long_level(u8 byte0, u32 version, int* level) {
  int t = packet_long_type(byte0, level_version_or_v1(version));
  if (t == PT_INITIAL) {
    *level = LEVEL_INITIAL;
    return 1;
  }
  if (t == PT_HANDSHAKE) {
    *level = LEVEL_HANDSHAKE;
    return 1;
  }
  return 0;
}

int connrunner_packet_level(u8 byte0, u32 version, int* level) {
  if (packet_is_long(byte0)) return long_level(byte0, version, level);
  *level = LEVEL_ONERTT; /* RFC 9000 17.3: short header is 1-RTT */
  return 1;
}
