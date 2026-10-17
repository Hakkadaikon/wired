#include "app/moqt/run/moqtssts_run_impl.h"

static int  moqtss_set_has(const moqtss_set* st, u64 alias);
static int  moqtss_set_is(const moqtss_set* st, u64 set_id);
static void moqtss_ring_clear(moqtss_set* st);
static usz  moqtss_insert_at(const moqtss_set* st, u64 kbps);

static int moqtss_set_has(const moqtss_set* st, u64 alias) {
  return st->in_use && moqtss_member_at(st, alias) >= 0;
}

/* Slot of the set holding alias, else -1 (a track is in one set). */
int moqtss_set_of_alias(const moqtss_sess* ss, u64 alias) {
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (moqtss_set_has(&ss->sets[k], alias)) return (int)k;
  return -1;
}

static int moqtss_set_is(const moqtss_set* st, u64 set_id) {
  return st->in_use && st->set_id == set_id;
}

int moqtss_set_by_id(const moqtss_sess* ss, u64 set_id) {
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (moqtss_set_is(&ss->sets[k], set_id)) return (int)k;
  return -1;
}

int moqtss_set_free(const moqtss_sess* ss) {
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (!ss->sets[k].in_use) return (int)k;
  return -1;
}

/* No decision recorded, no largest group: a fresh numbering. */
static void moqtss_ring_clear(moqtss_set* st) {
  for (usz i = 0; i < WIRED_MOQTRUN_SSTS_RING; i++) st->dec[i].used = 0;
  st->has_largest = 0;
}

/* The set set_id's slot, claimed fresh (empty, no decisions) when it does
 * not exist. The caller checked a slot is available (moqtss_room_in). */
usz moqtss_set_claim(moqtss_sess* ss, u64 set_id) {
  int k = moqtss_set_by_id(ss, set_id);
  if (k >= 0) return (usz)k;
  k                  = moqtss_set_free(ss);
  ss->sets[k].in_use = 1;
  ss->sets[k].set_id = set_id;
  ss->sets[k].n      = 0;
  moqtss_ring_clear(&ss->sets[k]);
  return (usz)k;
}

void moqtss_drop_if_empty(moqtss_sess* ss, usz k) {
  if (!ss->sets[k].n) ss->sets[k].in_use = 0;
}

void moqtss_member_remove(moqtss_set* st, usz i) {
  for (usz j = i + 1; j < st->n; j++) st->m[j - 1] = st->m[j];
  st->n--;
}

/* First index whose threshold exceeds kbps: the ascending insert point. */
static usz moqtss_insert_at(const moqtss_set* st, u64 kbps) {
  usz j = 0;
  while (j < st->n && st->m[j].threshold_kbps <= kbps) j++;
  return j;
}

/* Inserts (alias, kbps) keeping the ladder ascending; room was checked. */
void moqtss_member_insert(moqtss_set* st, u64 alias, u64 kbps) {
  usz j = moqtss_insert_at(st, kbps);
  for (usz i = st->n; i > j; i--) st->m[i] = st->m[i - 1];
  st->m[j].alias          = alias;
  st->m[j].threshold_kbps = kbps;
  st->n++;
}

void moqtss_unplace(moqtss_set* st, u64 alias) {
  int at = moqtss_member_at(st, alias);
  if (at >= 0) moqtss_member_remove(st, (usz)at);
}

/* alias leaves whatever set holds it; an emptied set is deleted. */
void moqtss_leave(moqtss_sess* ss, u64 alias) {
  int k = moqtss_set_of_alias(ss, alias);
  if (k < 0) return;
  moqtss_unplace(&ss->sets[k], alias);
  moqtss_drop_if_empty(ss, (usz)k);
  moqtss_sync_arm(ss);
}
