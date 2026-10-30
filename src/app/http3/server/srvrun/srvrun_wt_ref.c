#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_wt_ref_current(wired_wt_ref r);

/* Issue #185: give s, just opened, the env's next non-zero generation. */
void srvrun_wt_stamp(wired_srvrun_env* env, wired_wt_session* s) {
  env->wt_gen_last += 1 + (env->wt_gen_last == (u32)-1); /* 0 stays "none" */
  s->gen = env->wt_gen_last;
}

wired_wt_ref wired_wt_ref_of(wired_wt_session* s) {
  return (wired_wt_ref){s, s->gen};
}

/* r names a session open on a live connection of the caller's own env
 * (checked first, so another worker's session is never read) and is the
 * opening its storage holds now. */
static int srvrun_wt_ref_current(wired_wt_ref r) {
  return r.s && srvrun_session_conn(r.s) && r.s->gen == r.gen;
}

wired_wt_session* wired_wt_ref_get(wired_wt_ref r) {
  return r.gen && srvrun_wt_ref_current(r) ? r.s : 0;
}
