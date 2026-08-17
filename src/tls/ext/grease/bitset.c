#include "tls/ext/grease/bitset.h"

int greasebit_may_clear(int peer_advertised) {
  return peer_advertised != 0; /* RFC 9287 3 */
}

u8 greasebit_apply(u8 byte0, int clear) {
  if (clear) return (u8)(byte0 & ~BIT_MASK); /* RFC 9287 3 */
  return (u8)(byte0 | BIT_MASK);
}
