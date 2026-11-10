#include "transport/recovery/detect/recovery/ackdelay.h"

u64 ack_delay_encode(u64 micros, u8 exponent) {
  return micros >> exponent; /* scale down; low bits are lost as designed */
}
