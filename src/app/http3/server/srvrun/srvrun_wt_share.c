#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_wt_held(const srvrun_conn* c, int s);

/* Send slots held by session slot s (s < 0: connection plumbing). */
static int srvrun_wt_held(const srvrun_conn* c, int s) {
  int n = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    n += c->wtsend[i].in_use && c->wtsend[i].wt_session_slot == s;
  }
  return n;
}

/* Opening: session slot sidx may claim one more send slot while it holds
 * fewer than its share -- the slots plumbing does not hold, split evenly
 * among the active sessions -- so one session cannot fill the shared
 * table and starve the other's opens. */
int srvrun_wt_open_share_ok(const srvrun_conn* c, int sidx) {
  int n = 0;
  for (int s = 0; s < SRVRUN_MAX_WT_SESSIONS; s++) {
    n += srvrun_wt_is_active(c, s);
  }
  n += !n;
  return srvrun_wt_held(c, sidx) <
         ((int)SRVRUN_WT_SEND_SLOTS - srvrun_wt_held(c, -1)) / n;
}
