#include "app/http3/server/srvrun/srvrun_impl.h"

static int  srvrun_broadcast_fits(wired_span data);
static void srvrun_bcast_drain_one(
    srvrun_state* st, wired_srvinbox_ring* row, int j);
static int srvrun_bcast_drain_slot(void);
static int wt_slot_holds_session(srvrun_conn* c, int i, wired_wt_session* s);
static int srvrun_conn_owns_session(srvrun_conn* c, wired_wt_session* s);
static int conn_is_session_owner(srvrun_conn* c, wired_wt_session* s);
static int srvrun_session_conn_slot(wired_srvrun_env* env, wired_wt_session* s);

/* data.n fits every fan-out target's payload capacity (dg_pending_buf and
 * every wired_srvinbox_ring slot share the same 1200-byte cap by
 * construction, WIRED_SRVINBOX_SLOT_MAX). */
static int srvrun_broadcast_fits(wired_span data) {
  return data.n <= sizeof g_srvrun_state.conns[0].dg_pending_buf[0];
}

int wired_server_broadcast_datagram(wired_span data) {
  int slot;
  if (!srvrun_broadcast_fits(data)) return 0;
  slot = srvrun_bcast_find(wired_thread_tid());
  if (slot < 0) return srvrun_broadcast_direct(data);
  return srvrun_broadcast_registered(slot, data);
}

/* Pop at most one message from row[j] and, if there was one, fan it out to
 * st's local WT connections -- the loop body of srvrun_bcast_drain_self,
 * split out so the loop itself stays at the CCN gate. */
static void srvrun_bcast_drain_one(
    srvrun_state* st, wired_srvinbox_ring* row, int j) {
  u8  buf[WIRED_SRVINBOX_SLOT_MAX];
  usz n = wired_srvinbox_pop(&row[j], buf, sizeof buf);
  if (n) srvrun_broadcast_to_all(st, wired_span_of(buf, n));
}

/* This thread's own registry slot, or -1 if there is nothing to drain: fewer
 * than 2 workers registered (single-worker/default behavior is untouched,
 * mirroring wired_server_broadcast_datagram's own <= 1 guard) or the calling
 * thread never registered at all. */
static int srvrun_bcast_drain_slot(void) {
  if (__atomic_load_n(&g_srvrun_bcast_n, __ATOMIC_ACQUIRE) <= 1) return -1;
  return srvrun_bcast_find(wired_thread_tid());
}

/* Drain every ring in this worker's own inbox row into its local WT
 * connections -- one pop per source ring per call, matching the depth-4
 * ring's best-effort/bounded-catch-up shape (a source that published more
 * than one message since the last drain catches up over a few steps rather
 * than blocking this one). */
void srvrun_bcast_drain_self(srvrun_state* st) {
  int slot = srvrun_bcast_drain_slot();
  if (slot < 0) return;
  for (int j = 0; j < g_srvrun_bcast[slot].n_total; j++)
    srvrun_bcast_drain_one(st, g_srvrun_bcast[slot].inbox_row, j);
}

/* The env the calling thread's loop drives: a registered srvthreads worker's
 * own env (wired_srvrun_broadcast_register), else the process-wide
 * g_srvrun_env -- the same env-selection rule wired_server_broadcast_datagram
 * applies, reused by every session-addressed send API below (their session
 * pointer can only point into the caller's own loop's connection table). */
wired_srvrun_env* srvrun_caller_env(void) {
  int slot = srvrun_bcast_find(wired_thread_tid());
  return slot < 0 ? &g_srvrun_env : g_srvrun_bcast[slot].env;
}

/* Session slot i of c is active and IS s (pointer identity: every session
 * pointer this SDK hands to a callback points into a srvrun_conn's own
 * wt/wt1 storage, so identity is the exact reverse of srvrun_wt_slot). */
static int wt_slot_holds_session(srvrun_conn* c, int i, wired_wt_session* s) {
  return srvrun_wt_is_active(c, i) && srvrun_wt_slot(c, i) == s;
}

static int srvrun_conn_owns_session(srvrun_conn* c, wired_wt_session* s) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (wt_slot_holds_session(c, i, s)) return 1;
  return 0;
}

/* s's own slot index on c (0 or 1), or -1 if c does not own s -- the index
 * form of wt_slot_holds_session's search, needed wherever a caller must name
 * WHICH slot (wt_close_pending[sidx], srvrun_reset_wt_streams_for_session's
 * own session_slot param) rather than just whether c owns s at all. */
int srvrun_conn_session_slot(srvrun_conn* c, wired_wt_session* s) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (wt_slot_holds_session(c, i, s)) return i;
  return -1;
}

static int conn_is_session_owner(srvrun_conn* c, wired_wt_session* s) {
  return c->up && srvrun_conn_owns_session(c, s);
}

/* The connection slot in env whose active WT session storage is s, or -1
 * when no live connection owns it (a stale or foreign session pointer). */
static int srvrun_session_conn_slot(
    wired_srvrun_env* env, wired_wt_session* s) {
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++)
    if (conn_is_session_owner(&env->conns[i], s)) return (int)i;
  return -1;
}

/* Resolve s to its owning connection in the caller's env, also handing the
 * env and slot index back for the callers that need them (the datagram ring
 * keys entries by slot index). 0 when s is owned by no live connection. */
srvrun_conn* srvrun_session_conn_env(
    wired_wt_session* s, wired_srvrun_env** env_out, int* slot_out) {
  *env_out  = srvrun_caller_env();
  *slot_out = srvrun_session_conn_slot(*env_out, s);
  return *slot_out < 0 ? 0 : &(*env_out)->conns[*slot_out];
}

srvrun_conn* srvrun_session_conn(wired_wt_session* s) {
  wired_srvrun_env* env;
  int               slot;
  return srvrun_session_conn_env(s, &env, &slot);
}

/* Mark the free slot w in use, seeded with credit and no send state. */
srvrun_wtsend* srvrun_wtsend_take(srvrun_wtsend* w, u64 credit) {
  w->in_use        = 1;
  w->stream_credit = credit;
  /* Start from no send state, as srvrun_resp_claim does: a slot freed
   * mid-send (reset, STOP_SENDING) keeps its old sess and offsets. */
  w->sess             = (wired_sendsess){0};
  w->stream_off       = 0;
  w->append_open      = 0;
  w->view_round       = 0;
  w->fin_only_pending = 0; /* a reused slot may still carry a
                               stale 1 from its prior stream */
  w->fin_requested   = 0;
  w->urgency1        = 0;
  w->fine            = 0;
  w->flow            = 0;
  w->order           = 0;
  w->tie             = 0;
  w->wt_session_slot = -1;
  return w;
}
