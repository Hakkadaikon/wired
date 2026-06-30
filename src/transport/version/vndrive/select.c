#include "transport/version/vndrive/select.h"

#include "common/bytes/util/num.h"

int quic_vndrive_select(
    const u32 *offered,
    usz        n_off,
    const u32 *supported,
    usz        n_sup,
    u32       *chosen) {
  for (usz i = 0; i < n_sup; i++) {
    if (!quic_u32_in(supported[i], offered, n_off)) continue;
    *chosen = supported[i];
    return 1;
  }
  return 0;
}
