#include "app/http3/server/srvrun/srvrun_gen.h"
#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_wt_owned(const void* s, u32* cur_gen);

/* Issue #185: give s, just opened, the env's next non-zero generation. */
void srvrun_wt_stamp(wired_srvrun_env* env, wired_wt_session* s) {
  s->gen = srvrun_wt_gen_next(&env->wt_gen_last);
}

wired_wt_ref wired_wt_ref_of(wired_wt_session* s) {
  return (wired_wt_ref){s, s->gen};
}

/* s is open on a live connection of the caller's own env; *cur_gen is its
 * generation then (srvrun_wt_ref_resolves reads it only when owned). */
static int srvrun_wt_owned(const void* s, u32* cur_gen) {
  const wired_wt_session* session = s;
  if (!srvrun_session_conn((wired_wt_session*)session)) {
    return 0;
  }
  *cur_gen = session->gen;
  return 1;
}

wired_wt_session* wired_wt_ref_get(wired_wt_ref r) {
  return srvrun_wt_ref_resolves(r.s, r.gen, srvrun_wt_owned) ? r.s : 0;
}
