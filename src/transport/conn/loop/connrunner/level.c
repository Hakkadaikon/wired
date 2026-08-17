#include "transport/conn/loop/connrunner/level.h"

#include "crypto/kdf/keys/keyset.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/version/version/version.h"

/* RFC 9000 17.2: a long-header Initial or Handshake type maps to its keyset
 * level; 0-RTT and Retry are not driven by this loop. This loop runs before
 * a connection's negotiated version is otherwise known here, so it reads
 * type bits as v1 (VERSION_1); v2 packet-level classification is out of
 * scope until v2 connections are accepted. */
static int long_level(u8 byte0, int* level) {
  int t = packet_long_type(byte0, VERSION_1);
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

int connrunner_packet_level(u8 byte0, int* level) {
  if (packet_is_long(byte0)) return long_level(byte0, level);
  *level = LEVEL_ONERTT; /* RFC 9000 17.3: short header is 1-RTT */
  return 1;
}
