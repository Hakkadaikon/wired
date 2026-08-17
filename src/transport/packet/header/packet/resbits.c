#include "transport/packet/header/packet/resbits.h"

int resbits_ok(u8 byte0, int is_long) {
  u8 mask = is_long ? RESBITS_LONG : RESBITS_SHORT;
  return (byte0 & mask) == 0; /* reserved bits must be zero after unprotect */
}
