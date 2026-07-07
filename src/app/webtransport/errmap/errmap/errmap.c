#include "app/webtransport/errmap/errmap/errmap.h"

#define QUIC_WTERRMAP_FIRST 0x52e4a40fa8dbULL
#define QUIC_WTERRMAP_LAST 0x52e5ac983162ULL

u64 quic_wterrmap_to_http3(u32 n) {
  u64 wide = n; /* widen before arithmetic: first exceeds 32 bits, and doing
                 * the add/div in u32 would truncate long before promotion */
  return QUIC_WTERRMAP_FIRST + wide + wide / 0x1e;
}

static int wterrmap_in_range(u64 h) {
  return h >= QUIC_WTERRMAP_FIRST && h <= QUIC_WTERRMAP_LAST;
}

static int wterrmap_reserved(u64 h) { return (h - 0x21) % 0x1f == 0; }

int quic_wterrmap_from_http3(u64 h, u32* n_out) {
  if (!wterrmap_in_range(h) || wterrmap_reserved(h)) return 0;
  u64 shifted = h - QUIC_WTERRMAP_FIRST;
  *n_out      = (u32)(shifted - shifted / 0x1f);
  return 1;
}
