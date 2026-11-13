#include "app/moqt/run/moqtrun_impl.h"
#include "common/bytes/util/bits.h"

/* The word loops below index reqs[] by whole 64-slot words. */
_Static_assert(
    WIRED_MOQTRUN_MAX_REQS % 64 == 0, "reqs[] is a whole number of words");

static u64 moqtrun_req_used_word(const wired_moqt_hub* hub, usz w);
static u64 moqtrun_disc_live_word(const wired_moqt_hub* hub, u64 kind, usz w);

/* The in-use slots of reqs[64w .. 64w+63], one bit each. Branch-free: this
 * runs over every slot on every tick. */
static u64 moqtrun_req_used_word(const wired_moqt_hub* hub, usz w) {
  const wired_moqtrun_req* q    = &hub->reqs[w * 64];
  u64                      used = 0;
  for (usz b = 0; b < 64; b++) {
    used |= (u64)(q[b].in_use != 0) << b;
  }
  return used;
}

/* The live `kind` requests (moqtrun_disc_is) of the same 64 slots: only
 * the in-use ones are looked at. */
static u64 moqtrun_disc_live_word(const wired_moqt_hub* hub, u64 kind, usz w) {
  const wired_moqtrun_req* q    = &hub->reqs[w * 64];
  u64                      live = 0;
  for (u64 m = moqtrun_req_used_word(hub, w); m; m &= m - 1) {
    usz b = bits_ctz64(m);
    live |= ((u64)(q[b].live != 0) & (u64)(q[b].kind == kind)) << b;
  }
  return live;
}

/* Sets in mask (zeroed by the caller) the bit of every reqs[] slot that is
 * a live `kind` request, so a per-tick sync walks those few instead of all
 * WIRED_MOQTRUN_MAX_REQS. Returns 1 iff any bit is set. */
int moqtrun_disc_live_mask(const wired_moqt_hub* hub, u64 kind, u64* mask) {
  u64 any = 0;
  for (usz w = 0; w < WIRED_MOQTRUN_REQ_WORDS; w++) {
    mask[w] |= moqtrun_disc_live_word(hub, kind, w);
    any |= mask[w];
  }
  return any != 0;
}
