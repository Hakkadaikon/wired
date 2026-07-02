#include "transport/io/udp/udploop/antiamp_gate.h"

#include "transport/conn/cid/path/antiamp.h"

int quic_udploop_send_allowed(const quic_pathbudget *b, usz next_len) {
  if (b->address_validated) return 1; /* RFC 9000 8.1: no limit once validated */
  return quic_antiamp_can_send(b->received_bytes, b->sent_bytes, (u64)next_len);
}
