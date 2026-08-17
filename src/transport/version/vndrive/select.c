#include "transport/version/vndrive/select.h"

#include "common/bytes/util/num.h"

int vndrive_select(verlist offered, verlist supported, u32* chosen) {
  for (usz i = 0; i < supported.n; i++) {
    if (!u32_in(supported.list[i], offered.list, offered.n)) continue;
    *chosen = supported.list[i];
    return 1;
  }
  return 0;
}
