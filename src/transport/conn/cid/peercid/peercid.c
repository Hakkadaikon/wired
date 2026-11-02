#include "transport/conn/cid/peercid/peercid_impl.h"

static int                  peercid_hold(peercid* p, const ncid_frame* f);
static int                  peercid_is(const peercid_entry* e, u64 seq);
static const peercid_entry* peercid_held(const peercid* p, u64 seq);
static int peercid_same(const peercid_entry* e, const ncid_frame* f);
static int peercid_store(peercid* p, const ncid_frame* f);
static int peercid_below(const peercid_entry* e, u64 rpt);
static int peercid_drop_below(peercid* p, u64 rpt);
static int peercid_raise_rpt(peercid* p, u64 rpt);
static int peercid_take(peercid* p, const ncid_frame* f);

/* Hold cid as seq in a free entry. 0, or CONNECTION_ID_LIMIT_ERROR when
 * none is free (RFC 9000 5.1.1). */
static int peercid_hold(peercid* p, const ncid_frame* f) {
  for (usz i = 0; i < PEERCID_CAP; i++) {
    peercid_entry* e = &p->e[i];
    if (e->in_use) {
      continue;
    }
    *e = (peercid_entry){.seq = f->seq, .len = f->cid_len, .in_use = 1};
    bytes_memcpy(e->cid, f->cid, f->cid_len);
    bytes_memcpy(e->token, f->token, NCID_TOKEN);
    e->has_token = f->seq != 0; /* the handshake's ID carries none */
    return 0;
  }
  return ERR_CONNECTION_ID_LIMIT_ERROR;
}

void peercid_init(peercid* p, wired_span cid0) {
  ncid_frame f = {0};
  *p           = (peercid){0};
  p->empty     = cid0.n == 0;
  f.cid_len    = (u8)cid0.n;
  bytes_memcpy(f.cid, cid0.p, cid0.n);
  (void)peercid_hold(p, &f);
}

static int peercid_is(const peercid_entry* e, u64 seq) {
  return e->in_use && e->seq == seq;
}

/* The held entry for seq, or 0. */
static const peercid_entry* peercid_held(const peercid* p, u64 seq) {
  for (usz i = 0; i < PEERCID_CAP; i++) {
    if (peercid_is(&p->e[i], seq)) {
      return &p->e[i];
    }
  }
  return 0;
}

static int peercid_same(const peercid_entry* e, const ncid_frame* f) {
  return e->len == f->cid_len && ct_diffn(e->cid, f->cid, e->len) == 0;
}

/* RFC 9000 19.15: a repeat of a held sequence number is ignored when it
 * carries the same ID, a PROTOCOL_VIOLATION otherwise. */
static int peercid_store(peercid* p, const ncid_frame* f) {
  const peercid_entry* e = peercid_held(p, f->seq);
  if (e) {
    return peercid_same(e, f) ? 0 : ERR_PROTOCOL_VIOLATION;
  }
  return peercid_hold(p, f);
}

static int peercid_below(const peercid_entry* e, u64 rpt) {
  return e->in_use && e->seq < rpt;
}

/* Drop every ID below rpt. 1 if one could not be owed (queue full). */
static int peercid_drop_below(peercid* p, u64 rpt) {
  int full = 0;
  for (usz i = 0; i < PEERCID_CAP; i++) {
    if (peercid_below(&p->e[i], rpt)) {
      full |= !peercid_drop(p, &p->e[i]);
    }
  }
  return full;
}

/* Raise Retire Prior To to rpt. 1 if a retirement it forces found the
 * retire queue full. */
static int peercid_raise_rpt(peercid* p, u64 rpt) {
  if (rpt <= p->rpt) {
    return 0;
  }
  peercid_slide(p, rpt);
  return peercid_drop_below(p, rpt);
}

/* RFC 9000 5.1.2/19.15: a repeat of an ID already retired is ignored; one
 * below Retire Prior To is retired at once; any other is stored. */
static int peercid_take(peercid* p, const ncid_frame* f) {
  if (peercid_retired(p, f->seq)) {
    return 0;
  }
  if (f->seq < p->rpt) {
    return peercid_owe_err(p, f->seq);
  }
  return peercid_store(p, f);
}

int peercid_add(peercid* p, const ncid_frame* f) {
  if (p->empty) {
    return ERR_PROTOCOL_VIOLATION; /* RFC 9000 19.15 */
  }
  if (peercid_raise_rpt(p, f->retire_prior_to)) {
    return ERR_CONNECTION_ID_LIMIT_ERROR; /* RFC 9000 5.1.2 */
  }
  return peercid_take(p, f);
}
