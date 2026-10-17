#include "app/moqt/run/moqtswitch_impl.h"

/* SWITCH_FROM hub side: moqtswitch.h's file doc. TS-n cite the model's
 * requirements (tasks/loopeng/moqt/TrackSwitch/design.md). */

void moqtsw_sub_clear(wired_moqtrun_sub* s) {
  s->sw_role     = MOQTSW_ROLE_NONE;
  s->sw_mode     = 0;
  s->sw_done     = 0;
  s->sw_g        = 0;
  s->sw_peer_rid = 0;
  s->sw_deadline = 0;
}
