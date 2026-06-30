#include "transport/recovery/detect/recovery/ackdelay.h"

u64 quic_ack_delay_encode(u64 micros, u8 exponent) {
  return micros >> exponent; /* scale down; low bits are lost as designed */
}

u64 quic_ack_delay_decode(u64 value, u8 exponent) {
  return value << exponent; /* scale back up to microseconds */
}
