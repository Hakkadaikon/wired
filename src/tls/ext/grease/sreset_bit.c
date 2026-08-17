#include "tls/ext/grease/sreset_bit.h"

int greasebit_sreset_ok(u8 byte0) {
  (void)byte0; /* RFC 9287 3.1: any QUIC Bit value is acceptable */
  return 1;
}
