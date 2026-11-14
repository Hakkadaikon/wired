#include "app/moqt/run/moqtrun_impl.h"
#include "common/bytes/util/bits.h"

/* The word loops below index reqs[] by whole 64-slot words. */
_Static_assert(
    WIRED_MOQTRUN_MAX_REQS % 64 == 0, "reqs[] is a whole number of words");

static u64 moqtrun_disc_live_word(wired_moqt_hub* hub, u64 kind, usz w);
static u64 moqtrun_disc_ns_word(wired_moqt_hub* hub, usz w, u64* pubs);

/* The in-use slots of reqs[64w .. 64w+63], one bit each. Looks only at the
 * slots not known free (wired_moqt_hub.req_free) and remembers the free
 * ones it finds: several passes of every tick ask this. */
u64 moqtrun_req_used_word(wired_moqt_hub* hub, usz w) {
  const wired_moqtrun_req* q    = &hub->reqs[w * 64];
  u64                      used = 0;
  for (u64 m = ~hub->req_free[w]; m; m &= m - 1) {
    usz b = bits_ctz64(m);
    used |= (u64)(q[b].in_use != 0) << b;
  }
  hub->req_free[w] = ~used;
  return used;
}

/* The live `kind` requests (moqtrun_disc_is) of the same 64 slots: only
 * the in-use ones are looked at. */
static u64 moqtrun_disc_live_word(wired_moqt_hub* hub, u64 kind, usz w) {
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
int moqtrun_disc_live_mask(wired_moqt_hub* hub, u64 kind, u64* mask) {
  u64 any = 0;
  for (usz w = 0; w < WIRED_MOQTRUN_REQ_WORDS; w++) {
    mask[w] |= moqtrun_disc_live_word(hub, kind, w);
    any |= mask[w];
  }
  return any != 0;
}

/* moqtrun_disc_live_word for SUBSCRIBE_NAMESPACE (returned) and
 * PUBLISH_NAMESPACE (*pubs) from one walk of the word's in-use slots. */
static u64 moqtrun_disc_ns_word(wired_moqt_hub* hub, usz w, u64* pubs) {
  const wired_moqtrun_req* q    = &hub->reqs[w * 64];
  u64                      subs = 0;
  for (u64 m = moqtrun_req_used_word(hub, w); m; m &= m - 1) {
    usz b    = bits_ctz64(m);
    u64 live = q[b].live != 0;
    subs |= (live & (u64)(q[b].kind == MOQNS_T_SUBSCRIBE_NAMESPACE)) << b;
    *pubs |= (live & (u64)(q[b].kind == MOQNS_T_PUBLISH_NAMESPACE)) << b;
  }
  return subs;
}

/* The two masks moqtrun_disc_sync needs (both zeroed by the caller), as
 * two moqtrun_disc_live_mask calls would fill them, from one walk of
 * reqs[]. Returns 1 iff there is a live SUBSCRIBE_NAMESPACE. */
int moqtrun_disc_ns_masks(wired_moqt_hub* hub, u64* subs, u64* pubs) {
  u64 any = 0;
  for (usz w = 0; w < WIRED_MOQTRUN_REQ_WORDS; w++) {
    subs[w] |= moqtrun_disc_ns_word(hub, w, &pubs[w]);
    any |= subs[w];
  }
  return any != 0;
}
