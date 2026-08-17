#include "transport/conn/cid/path/antiamp.h"

u64 antiamp_budget(u64 received, u64 sent) {
  u64 cap = 3 * received;
  if (sent >= cap) return 0;
  return cap - sent;
}

int antiamp_can_send(u64 received, u64 sent, u64 want) {
  return want <= antiamp_budget(received, sent);
}
