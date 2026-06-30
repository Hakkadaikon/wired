#include "transport/conn/cid/spin/spin.h"

int quic_spin_outgoing(int is_server, int peer_spin) {
  /* server reflects the received bit; client sends its inverse */
  return is_server ? (peer_spin & 1) : ((peer_spin & 1) ^ 1);
}

int quic_spin_get(u8 byte0) { return (byte0 & QUIC_SPIN_BIT) != 0; }

u8 quic_spin_set(u8 byte0, int spin) {
  u8 cleared = byte0 & (u8)~QUIC_SPIN_BIT;
  return spin ? (cleared | QUIC_SPIN_BIT) : cleared;
}
