#include "transport/conn/cid/path/antiamp.h"

u64 quic_antiamp_budget(u64 received, u64 sent) {
  u64 cap = 3 * received;
  if (sent >= cap) return 0;
  return cap - sent;
}

int quic_antiamp_can_send(u64 received, u64 sent, u64 want) {
  return want <= quic_antiamp_budget(received, sent);
}
