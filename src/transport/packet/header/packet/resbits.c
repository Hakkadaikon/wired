#include "transport/packet/header/packet/resbits.h"

int quic_resbits_ok(u8 byte0, int is_long) {
  u8 mask = is_long ? QUIC_RESBITS_LONG : QUIC_RESBITS_SHORT;
  return (byte0 & mask) == 0; /* reserved bits must be zero after unprotect */
}
