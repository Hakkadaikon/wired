#include "app/moqt/run/moqtswitch_impl.h"

static int moqtsw_step_track(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    u32*                 live);
static int moqtsw_step_peer(
    wired_moqt_hub*     hub,
    const moqtsw_ops*   ops,
    wired_moqtrun_peer* p,
    u32*                live);

static int moqtsw_step_track(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    u32*                 live) {
  int n = 0;
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++) {
    n += moqtsw_visit(hub, ops, t, si, live);
  }
  return n;
}

static int moqtsw_step_peer(
    wired_moqt_hub*     hub,
    const moqtsw_ops*   ops,
    wired_moqtrun_peer* p,
    u32*                live) {
  int n = 0;
  if (!p->in_use) {
    return 0;
  }
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    n += moqtsw_step_track(hub, ops, &p->tracks[t], live);
  }
  return n;
}

/* hub->sw_live is a hint (switches begun since the last sweep, plus the
 * ones it left waiting): 0 skips the walk, each walk recounts it. */
int moqtsw_step(wired_moqt_hub* hub, const moqtsw_ops* ops) {
  int n    = 0;
  u32 live = 0;
  if (!hub->sw_live) {
    return 0;
  }
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    n += moqtsw_step_peer(hub, ops, &hub->peers[i], &live);
  }
  hub->sw_live = live;
  return n;
}

u64 moqtsw_done_code(int ver, u64 status) {
  return status == MOQTSW_DONE_SWITCHED ? MOQCTL_DONE_SWITCHED
                                        : moqctl_publish_done_for(ver, status);
}
