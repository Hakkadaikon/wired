#include "transport/conn/loop/connrunner/level.h"

#include "crypto/kdf/keys/keyset.h"
#include "transport/packet/header/packet/ptype.h"

/* RFC 9000 17.2: a long-header Initial or Handshake type maps to its keyset
 * level; 0-RTT and Retry are not driven by this loop. */
static int long_level(u8 byte0, int* level) {
  int t = quic_packet_long_type(byte0);
  if (t == QUIC_PT_INITIAL) {
    *level = QUIC_LEVEL_INITIAL;
    return 1;
  }
  if (t == QUIC_PT_HANDSHAKE) {
    *level = QUIC_LEVEL_HANDSHAKE;
    return 1;
  }
  return 0;
}

int quic_connrunner_packet_level(u8 byte0, int* level) {
  if (quic_packet_is_long(byte0)) return long_level(byte0, level);
  *level = QUIC_LEVEL_ONERTT; /* RFC 9000 17.3: short header is 1-RTT */
  return 1;
}
