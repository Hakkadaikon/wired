#include "transport/conn/loop/manage/flowobs.h"

#include "transport/packet/header/packet/ptype.h"

int quic_manage_is_vneg(u8 byte0, u32 version) {
  /* RFC 9000 17.2.1: long header with a zero version field. */
  return quic_packet_is_long(byte0) && version == 0;
}

int quic_manage_is_flow_start(u8 byte0, u32 version) {
  if (version == 0) return 0; /* Version Negotiation, not a start */
  return quic_packet_long_type(byte0) == QUIC_PT_INITIAL; /* RFC 9312 3.3 */
}
