#include "app/http3/server/srvrun/srvrun_impl.h"

static int  srvrun_is_broadcast_target(const srvrun_conn* c);
static i64  srvrun_bcast_tid(int i);
static int  srvrun_bcast_try_claim(int i);
static int  srvrun_bcast_claim(void);
static int  srvrun_bcast_mesh_target(int t, int my_slot);
static void srvrun_bcast_mesh_push(int my_slot, int my_index, wired_span data);

/* c is a live connection with at least one active WT session -- a broadcast
 * target. Split out of srvrun_broadcast_to_all to keep its own branch count
 * at the CCN gate (mirrors srvrun_owes_goaway's own role for
 * srvrun_goaway_all). */
static int srvrun_is_broadcast_target(const srvrun_conn* c) {
  return c->up && srvrun_wt_any_active(c);
}

/* Queue data into every connection with an active WT session's own single-
 * slot DATAGRAM queue (srvrun_queue_datagram) -- mirrors srvrun_goaway_all's
 * fan-out shape, swapping the goaway-owed guard for wt_active. Each
 * connection still drains through its own srvrun_send_pending_datagram on
 * its own next step, same as any other queued datagram; this only makes
 * every eligible connection's slot hold the same payload at once. */
void srvrun_broadcast_to_all(srvrun_state* st, wired_span data) {
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++)
    if (srvrun_is_broadcast_target(&st->conns[i]))
      srvrun_queue_datagram(&st->conns[i], data);
}

srvrun_bcast_entry g_srvrun_bcast[SRVRUN_BCAST_MAX];

int g_srvrun_bcast_n; /* registered entry count (atomic) */

/* Slot i's published tid (acquire: pairs with the registrant's release). */
static i64 srvrun_bcast_tid(int i) {
  return __atomic_load_n(&g_srvrun_bcast[i].tid, __ATOMIC_ACQUIRE);
}

/* Registry slot index for tid (> 0), or -1 if tid is not registered. */
int srvrun_bcast_find(i64 tid) {
  for (int i = 0; i < SRVRUN_BCAST_MAX; i++)
    if (srvrun_bcast_tid(i) == tid) return i;
  return -1;
}

/* Claim slot i for a registrant: CAS free -> CLAIMING, so two workers
 * registering at once can never both take it. 1 on success. */
static int srvrun_bcast_try_claim(int i) {
  i64 want = 0;
  return __atomic_compare_exchange_n(
      &g_srvrun_bcast[i].tid, &want, SRVRUN_BCAST_CLAIMING, 0, __ATOMIC_ACQ_REL,
      __ATOMIC_RELAXED);
}

/* The first slot this thread claimed, -1 when the registry is full. */
static int srvrun_bcast_claim(void) {
  for (int i = 0; i < SRVRUN_BCAST_MAX; i++)
    if (srvrun_bcast_try_claim(i)) return i;
  return -1;
}

void wired_srvrun_broadcast_register(
    int                  index,
    int                  n_total,
    wired_srvinbox_ring* inbox_row,
    wired_srvrun_env*    env) {
  i64                 tid = wired_thread_tid();
  int                 slot;
  srvrun_bcast_entry* e;
  if (srvrun_bcast_find(tid) >= 0) return; /* already registered */
  slot = srvrun_bcast_claim();
  if (slot < 0) return; /* registry full, drop the registration */
  e          = &g_srvrun_bcast[slot];
  e->index   = index;
  e->n_total = n_total;
  e->env     = env;
  /* atomic: a reader holding a stale tid of a slot unregistered and
   * re-claimed meanwhile (ABA, only possible when a worker fails early
   * while others are still registering) may read it concurrently; it then
   * pushes into the new, live owner's row -- never a torn pointer. */
  __atomic_store_n(&e->inbox_row, inbox_row, __ATOMIC_RELAXED);
  __atomic_store_n(&e->tid, tid, __ATOMIC_RELEASE); /* publish */
  __atomic_add_fetch(&g_srvrun_bcast_n, 1, __ATOMIC_ACQ_REL);
}

void wired_srvrun_broadcast_unregister(void) {
  int slot = srvrun_bcast_find(wired_thread_tid());
  if (slot < 0) return;
  __atomic_store_n(&g_srvrun_bcast[slot].tid, 0, __ATOMIC_RELEASE);
  __atomic_sub_fetch(&g_srvrun_bcast_n, 1, __ATOMIC_ACQ_REL);
}

/* t is a mesh push target: a registered slot other than the caller's own. */
static int srvrun_bcast_mesh_target(int t, int my_slot) {
  return srvrun_bcast_tid(t) > 0 && t != my_slot; /* CLAIMING: not yet */
}

/* Push data into every OTHER registered worker t's inbox row at column
 * my_index (the caller's own mesh index) -- best-effort per target, mirroring
 * srvrun_broadcast_to_all's own best-effort per-connection queuing. The
 * caller's own connections are reached directly by srvrun_broadcast_registered
 * instead (its own env's table), not through this mesh push -- pushing into
 * its own row here too would double-deliver: once now via the direct
 * fan-out, once more next step when it drains its own inbox row. my_slot
 * lets the loop skip exactly the caller's own registry entry. */
static void srvrun_bcast_mesh_push(int my_slot, int my_index, wired_span data) {
  for (int t = 0; t < SRVRUN_BCAST_MAX; t++) {
    if (!srvrun_bcast_mesh_target(t, my_slot)) continue;
    wired_srvinbox_push(
        &__atomic_load_n(
            &g_srvrun_bcast[t].inbox_row, __ATOMIC_RELAXED)[my_index],
        data.p, data.n);
  }
}

/* Single-process fallback path: the calling thread is not registered (no
 * srvthreads worker ever called wired_srvrun_broadcast_register), so this is
 * either wired_server_run(_opt) or the one-and-only wired_srvrun_serve_env
 * instance -- both drive the single process-wide g_srvrun_env. */
int srvrun_broadcast_direct(wired_span data) {
  srvrun_broadcast_to_all(
      &(srvrun_state){g_srvrun_table, g_srvrun_state.conns}, data);
  return 1;
}

/* A registered srvthreads worker (any n_total, including 1): fan out to the
 * calling worker's OWN env (its own connection table) first -- the env a
 * plain g_srvrun_env-based fan-out would completely miss, since srvthreads
 * gives every worker its own mmap'd env instead of the single global one.
 * With 2+ workers also push into every OTHER registered worker's inbox row
 * so their own next step delivers it to their own sessions. */
int srvrun_broadcast_registered(int slot, wired_span data) {
  srvrun_bcast_entry* e = &g_srvrun_bcast[slot];
  srvrun_broadcast_to_all(&(srvrun_state){e->env->table, e->env->conns}, data);
  if (e->n_total > 1) srvrun_bcast_mesh_push(slot, e->index, data);
  return 1;
}
