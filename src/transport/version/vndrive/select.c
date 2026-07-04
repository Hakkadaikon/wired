#include "transport/version/vndrive/select.h"

#include "common/bytes/util/num.h"

int quic_vndrive_select(
    quic_verlist offered, quic_verlist supported, u32* chosen) {
  for (usz i = 0; i < supported.n; i++) {
    if (!quic_u32_in(supported.list[i], offered.list, offered.n)) continue;
    *chosen = supported.list[i];
    return 1;
  }
  return 0;
}
