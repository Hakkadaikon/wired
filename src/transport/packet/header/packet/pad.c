#include "transport/packet/header/packet/pad.h"

usz pad_needed(usz cur_len) {
  if (cur_len >= MIN_INITIAL_DATAGRAM) return 0;
  return MIN_INITIAL_DATAGRAM - cur_len;
}
