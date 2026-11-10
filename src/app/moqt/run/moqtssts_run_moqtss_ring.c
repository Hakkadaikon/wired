#include "app/moqt/run/moqtssts_run_impl.h"

static int         moqtss_dec_stale(const moqtss_set* st, const moqtss_dec* e);
static int         moqtss_dec_hit(const moqtss_dec* e, u64 g);
static void        moqtss_ring_prune(moqtss_set* st);
static moqtss_dec* moqtss_ring_slot(moqtss_set* st);
static void        moqtss_note_largest(moqtss_set* st, u64 g);

/* ===== decisions (controller.rs, mod.rs record_group_decision) ===== */

/* Older than the set's largest - KEEP: pruned (moqtail DECISION_WINDOW). */
static int moqtss_dec_stale(const moqtss_set* st, const moqtss_dec* e) {
  return e->group + WIRED_MOQTRUN_SSTS_KEEP < st->largest;
}

static int moqtss_dec_hit(const moqtss_dec* e, u64 g) {
  return e->used && e->group == g;
}

const moqtss_dec* moqtss_ring_find(const moqtss_set* st, u64 g) {
  for (usz i = 0; i < WIRED_MOQTRUN_SSTS_RING; i++) {
    if (moqtss_dec_hit(&st->dec[i], g)) {
      return &st->dec[i];
    }
  }
  return 0;
}

/* moqtail record_group_decision: entries older than largest - KEEP go
 * whenever a decision is recorded (the one being written is kept). */
static void moqtss_ring_prune(moqtss_set* st) {
  for (usz i = 0; i < WIRED_MOQTRUN_SSTS_RING; i++) {
    if (moqtss_dec_stale(st, &st->dec[i])) {
      st->dec[i].used = 0;
    }
  }
}

/* A free entry. One always is: moqtss_ring_prune leaves only groups in
 * [largest - KEEP, largest], each recorded once (a group is recorded
 * only when moqtss_ring_find missed it), so at most KEEP + 1 < RING are
 * used here; the last entry stands in for that invariant. */
static moqtss_dec* moqtss_ring_slot(moqtss_set* st) {
  for (usz i = 0; i < WIRED_MOQTRUN_SSTS_RING - 1; i++) {
    if (!st->dec[i].used) {
      return &st->dec[i];
    }
  }
  return &st->dec[WIRED_MOQTRUN_SSTS_RING - 1];
}

static void moqtss_note_largest(moqtss_set* st, u64 g) {
  st->largest     = st->has_largest ? u64_max(st->largest, g) : g;
  st->has_largest = 1;
}

void moqtss_ring_record(moqtss_set* st, u64 g, u64 pick) {
  moqtss_note_largest(st, g);
  moqtss_ring_prune(st);
  moqtss_dec* e = moqtss_ring_slot(st);
  e->used       = 1;
  e->group      = g;
  e->pick       = pick;
}

void moqtss_view_add(
    const wired_moqt_hub* hub,
    moqtss_view*          v,
    const moqtss_set*     st,
    usz                   sidx,
    usz                   k) {
  moqssts_set* d  = &v->sets[v->n];
  d->set_id       = st->set_id;
  d->algorithm_id = st->algorithm_id;
  d->weight       = st->weight;
  d->activate     = st->activate;
  d->rank         = st->rank;
  d->n_members    = st->n;
  for (usz i = 0; i < st->n; i++) {
    d->m[i].track_id       = st->m[i].alias;
    d->m[i].threshold_kbps = st->m[i].threshold_kbps;
  }
  v->open[v->n] = moqtss_set_open(hub, st, sidx);
  v->slot[v->n] = k;
  v->n++;
}
