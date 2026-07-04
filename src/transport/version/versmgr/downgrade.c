#include "transport/version/versmgr/downgrade.h"

#include "transport/version/version/availfilter.h"

/* +1 keep scanning, 0 reached negotiated (ok), -1 a usable version precedes
 * it (RFC 9368 6 downgrade). */
static int scan_step(u32 v, u32 negotiated) {
  if (v == negotiated) return 0;
  return quic_verinfo_is_usable(v) ? -1 : 1;
}

int quic_vers_no_downgrade(u32 negotiated, const u32* server_available, usz n) {
  for (usz i = 0; i < n; i++) {
    int step = scan_step(server_available[i], negotiated);
    if (step <= 0) return step == 0;
  }
  return 0; /* RFC 9368 6: negotiated not offered by the server */
}
