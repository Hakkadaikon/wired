#include "transport/conn/cid/peercid/peercid.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "common/diag/error/error.h"

/* Hold cid as seq in a free entry. 0, or CONNECTION_ID_LIMIT_ERROR when
 * none is free (RFC 9000 5.1.1). */
static int peercid_hold(peercid* p, u64 seq, const u8* cid, u8 len) {
  for (usz i = 0; i < PEERCID_CAP; i++) {
    peercid_entry* e = &p->e[i];
    if (e->in_use) continue;
    *e = (peercid_entry){.seq = seq, .len = len, .in_use = 1};
    bytes_memcpy(e->cid, cid, len);
    return 0;
  }
  return ERR_CONNECTION_ID_LIMIT_ERROR;
}

void peercid_init(peercid* p, wired_span cid0) {
  *p       = (peercid){0};
  p->empty = cid0.n == 0;
  (void)peercid_hold(p, 0, cid0.p, (u8)cid0.n);
}

/* ponytail: a full retire queue drops the frame; the peer then keeps an ID
 * active and issues fewer new ones. */
static void peercid_owe(peercid* p, u64 seq) {
  if (p->retire_n < PEERCID_RETIRE) p->retire[p->retire_n++] = seq;
}

/* seq's bit in gone, or 0 outside [rpt, rpt + 64). ponytail: an ID retired
 * further ahead is held again if its frame repeats; widen gone if a peer
 * issues that far ahead. */
static u64 peercid_bit(const peercid* p, u64 seq) {
  u64 d = seq - p->rpt;
  return d < 64 ? (u64)1 << d : 0;
}

static void peercid_drop(peercid* p, peercid_entry* e) {
  peercid_owe(p, e->seq);
  p->gone |= peercid_bit(p, e->seq);
  e->in_use = 0;
}

static int peercid_is(const peercid_entry* e, u64 seq) {
  return e->in_use && e->seq == seq;
}

/* The held entry for seq, or 0. */
static const peercid_entry* peercid_held(const peercid* p, u64 seq) {
  for (usz i = 0; i < PEERCID_CAP; i++)
    if (peercid_is(&p->e[i], seq)) return &p->e[i];
  return 0;
}

static int peercid_same(const peercid_entry* e, const ncid_frame* f) {
  return e->len == f->cid_len && ct_diffn(e->cid, f->cid, e->len) == 0;
}

/* RFC 9000 19.15: a repeat of a held sequence number is ignored when it
 * carries the same ID, a PROTOCOL_VIOLATION otherwise. */
static int peercid_store(peercid* p, const ncid_frame* f) {
  const peercid_entry* e = peercid_held(p, f->seq);
  if (e) return peercid_same(e, f) ? 0 : ERR_PROTOCOL_VIOLATION;
  return peercid_hold(p, f->seq, f->cid, f->cid_len);
}

static int peercid_below(const peercid_entry* e, u64 rpt) {
  return e->in_use && e->seq < rpt;
}

static void peercid_drop_below(peercid* p, u64 rpt) {
  for (usz i = 0; i < PEERCID_CAP; i++)
    if (peercid_below(&p->e[i], rpt)) peercid_drop(p, &p->e[i]);
}

static void peercid_raise_rpt(peercid* p, u64 rpt) {
  if (rpt <= p->rpt) return;
  p->gone = rpt - p->rpt < 64 ? p->gone >> (rpt - p->rpt) : 0;
  p->rpt  = rpt;
  peercid_drop_below(p, rpt);
}

/* RFC 9000 5.1.2/19.15: an ID below Retire Prior To is retired at once; a
 * repeat of one already retired is ignored; any other is stored. */
static int peercid_take(peercid* p, const ncid_frame* f) {
  if (f->seq < p->rpt) {
    peercid_owe(p, f->seq);
    return 0;
  }
  if (p->gone & peercid_bit(p, f->seq)) return 0;
  return peercid_store(p, f);
}

int peercid_add(peercid* p, const ncid_frame* f) {
  if (p->empty) return ERR_PROTOCOL_VIOLATION; /* RFC 9000 19.15 */
  peercid_raise_rpt(p, f->retire_prior_to);
  return peercid_take(p, f);
}

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
