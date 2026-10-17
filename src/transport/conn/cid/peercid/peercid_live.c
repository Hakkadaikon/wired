#include "transport/conn/cid/peercid/peercid_impl.h"

static int peercid_live(const peercid_entry* e);
static int peercid_owns(const peercid_entry* e, const pathsel_key* k);
static int peercid_shares(const peercid_entry* e, const pathsel_key* k);
static int peercid_serves(const peercid_entry* e, const pathsel_key* k);
static peercid_entry*       peercid_own(peercid* p, const pathsel_key* k);
static const peercid_entry* peercid_shared(
    const peercid* p, const pathsel_key* k);
static int peercid_unbound(const peercid_entry* e);
static int peercid_better(const peercid_entry* e, const peercid_entry* best);
static peercid_entry*       peercid_oldest_free(peercid* p);
static const peercid_entry* peercid_claim(peercid* p, const pathsel_key* k);
static int                  peercid_used(
    const peercid_entry* e, const pathsel_key* tracked, usz n);
static int peercid_stale(
    const peercid_entry* e, const pathsel_key* tracked, usz n);

static int peercid_live(const peercid_entry* e) {
  return e->in_use && e->bound;
}

/* e is bound to exactly k. */
static int peercid_owns(const peercid_entry* e, const pathsel_key* k) {
  return peercid_live(e) && pathsel_key_eq(&e->key, k);
}

/* e is shared on k's socket. */
static int peercid_shares(const peercid_entry* e, const pathsel_key* k) {
  return peercid_live(e) && e->shared && e->key.fd == k->fd;
}

static int peercid_serves(const peercid_entry* e, const pathsel_key* k) {
  return peercid_owns(e, k) || peercid_shares(e, k);
}

static peercid_entry* peercid_own(peercid* p, const pathsel_key* k) {
  for (usz i = 0; i < PEERCID_CAP; i++)
    if (peercid_owns(&p->e[i], k)) return &p->e[i];
  return 0;
}

static const peercid_entry* peercid_shared(
    const peercid* p, const pathsel_key* k) {
  for (usz i = 0; i < PEERCID_CAP; i++)
    if (peercid_shares(&p->e[i], k)) return &p->e[i];
  return 0;
}

const peercid_entry* peercid_of(const peercid* p, const pathsel_key* k) {
  const peercid_entry* e = peercid_own((peercid*)p, k);
  return e ? e : peercid_shared(p, k);
}

/* e is free to bind and older than best (or best is 0). */
static int peercid_unbound(const peercid_entry* e) {
  return e->in_use && !e->bound;
}

static int peercid_better(const peercid_entry* e, const peercid_entry* best) {
  if (!peercid_unbound(e)) return 0;
  return !best || e->seq < best->seq;
}

/* The unbound ID with the lowest sequence number, or 0. */
static peercid_entry* peercid_oldest_free(peercid* p) {
  peercid_entry* best = 0;
  for (usz i = 0; i < PEERCID_CAP; i++)
    if (peercid_better(&p->e[i], best)) best = &p->e[i];
  return best;
}

static const peercid_entry* peercid_claim(peercid* p, const pathsel_key* k) {
  const peercid_entry* cur = peercid_own(p, k);
  peercid_entry*       e;
  if (cur) return cur;
  e = peercid_oldest_free(p);
  if (!e) return 0;
  e->key   = *k;
  e->bound = 1;
  return e;
}

const peercid_entry* peercid_bind(peercid* p, const pathsel_key* k) {
  return p->empty ? &p->e[0] : peercid_claim(p, k);
}

const peercid_entry* peercid_share(peercid* p, const pathsel_key* cur) {
  peercid_entry* e = (peercid_entry*)peercid_of(p, cur);
  if (e) e->shared = 1;
  return e;
}

static int peercid_used(
    const peercid_entry* e, const pathsel_key* tracked, usz n) {
  for (usz i = 0; i < n; i++)
    if (peercid_serves(e, &tracked[i])) return 1;
  return 0;
}

static int peercid_stale(
    const peercid_entry* e, const pathsel_key* tracked, usz n) {
  return peercid_live(e) && !peercid_used(e, tracked, n);
}

void peercid_sweep(peercid* p, const pathsel_key* tracked, usz n) {
  for (usz i = 0; i < PEERCID_CAP; i++)
    if (peercid_stale(&p->e[i], tracked, n)) peercid_drop(p, &p->e[i]);
}

int peercid_take_retire(peercid* p, u64* seq) {
  if (!p->retire_n) return 0;
  *seq = p->retire[0];
  p->retire_n--;
  for (usz i = 0; i < p->retire_n; i++) p->retire[i] = p->retire[i + 1];
  return 1;
}
