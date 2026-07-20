#include "transport/packet/header/packet/ptype.h"

#include "transport/version/version/v2types.h"

int quic_packet_is_long(u8 byte0) {
  return (byte0 & 0x80) != 0; /* RFC 9000 17.2 header form bit */
}

/* Wire type bits (5-4 of byte 0), independent of version. */
static int wire_bits(u8 byte0) { return (byte0 >> 4) & 0x3; }

/* Wire-to-logical mapping for `version`, or QUIC_LT_INVALID if this SDK does
 * not know the type-bit layout for `version` (RFC 9000 17.2 for v1, RFC
 * 9369 3.2 for v2; other versions are not interpreted here). */
static quic_logical_type logical_for(int wire, u32 version) {
  if (version == QUIC_VERSION_1) return quic_v1_logical_type(wire);
  if (version == QUIC_VERSION_2) return quic_v2_logical_type(wire);
  return QUIC_LT_INVALID;
}

int quic_packet_long_type(u8 byte0, u32 version) {
  quic_logical_type lt;
  if (!quic_packet_is_long(byte0)) return QUIC_PT_NONE;
  lt = logical_for(wire_bits(byte0), version);
  return lt == QUIC_LT_INVALID ? QUIC_PT_NONE : (int)lt;
}
