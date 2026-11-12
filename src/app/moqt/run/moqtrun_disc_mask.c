#include "app/moqt/run/moqtrun_impl.h"

/* Sets in mask (zeroed by the caller) the bit of every reqs[] slot that is
 * a live `kind` request, so a per-tick sync walks those few instead of all
 * WIRED_MOQTRUN_MAX_REQS. Returns 1 iff any bit is set. */
int moqtrun_disc_live_mask(const wired_moqt_hub* hub, u64 kind, u64* mask) {
  u64 any = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    if (moqtrun_disc_is(&hub->reqs[i], kind)) {
      mask[i / 64] |= (u64)1 << (i % 64);
      any = 1;
    }
  }
  return (int)any;
}
