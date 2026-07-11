#include "app/http3/server/srvinbox/srvinbox.h"

#include "common/bytes/util/bytes.h"

void wired_srvinbox_ring_init(wired_srvinbox_ring* r) {
  r->prod = 0;
  r->cons = 0;
}

/* 1 if the ring is full per the given (possibly stale) cons value: exactly
 * WIRED_SRVINBOX_DEPTH published messages not yet released. */
static int srvinbox_full_at(u32 prod, u32 cons) {
  return prod - cons == WIRED_SRVINBOX_DEPTH;
}

/* 1 if the ring is empty per the given (possibly stale) prod value: no
 * published message past cons yet. */
static int srvinbox_empty_at(u32 prod, u32 cons) {
  return cons == prod;
}

/* Producer-side full check, reloading cons (ACQUIRE) exactly once if the
 * producer's own first look shows full -- tasks/loopeng/srvinbox-mesh
 * S-001/S-002/S-013: drop is decided against the reloaded value, never a
 * stale look alone. Every load of the shared cons cell is ACQUIRE, never a
 * plain non-atomic read (which would race the consumer's RELEASE store and
 * carry no synchronizes-with edge to the slot data the consumer is about to
 * read). wired_srvinbox_ring has no xskring.c-style per-side cached_cons
 * field (the push/pop API is stateless across calls, unlike xskring's
 * reserve/submit split), so there is no cheaper look to fall back to here;
 * the two-look shape is kept anyway to match the TLA+ model's PBegin/
 * PRecheck split 1:1 -- both loads are ACQUIRE, so the second is a genuine
 * re-read rather than an upgrade from a weaker one. Returns 1 (still full
 * after any reload) or 0 (room). */
static int srvinbox_prod_full(u32 prod, const wired_srvinbox_ring* r) {
  u32 cons = __atomic_load_n(&r->cons, __ATOMIC_ACQUIRE);
  if (!srvinbox_full_at(prod, cons)) return 0;
  cons = __atomic_load_n(&r->cons, __ATOMIC_ACQUIRE);
  return srvinbox_full_at(prod, cons);
}

int wired_srvinbox_push(wired_srvinbox_ring* r, const u8* data, usz len) {
  u32                  prod = __atomic_load_n(&r->prod, __ATOMIC_RELAXED);
  wired_srvinbox_slot* slot;
  if (len > WIRED_SRVINBOX_SLOT_MAX) return 0;
  if (srvinbox_prod_full(prod, r)) return 0;
  slot = &r->slots[prod & (WIRED_SRVINBOX_DEPTH - 1)];
  quic_memcpy(slot->buf, data, len);
  slot->len = len;
  __atomic_store_n(&r->prod, prod + 1, __ATOMIC_RELEASE);
  return 1;
}

/* Consumer-side empty check, reloading prod (ACQUIRE) exactly once if the
 * consumer's own first look shows empty -- S-005 mirror of
 * srvinbox_prod_full, same every-load-is-ACQUIRE rationale (a synchronizes-
 * with edge to the producer's slot write is required before the slot read
 * below, not just a fresh-looking value). */
static int srvinbox_cons_empty(u32 cons, const wired_srvinbox_ring* r) {
  u32 prod = __atomic_load_n(&r->prod, __ATOMIC_ACQUIRE);
  if (!srvinbox_empty_at(prod, cons)) return 0;
  prod = __atomic_load_n(&r->prod, __ATOMIC_ACQUIRE);
  return srvinbox_empty_at(prod, cons);
}

usz wired_srvinbox_pop(wired_srvinbox_ring* r, u8* out_buf, usz out_cap) {
  u32                  cons = __atomic_load_n(&r->cons, __ATOMIC_RELAXED);
  wired_srvinbox_slot* slot;
  if (srvinbox_cons_empty(cons, r)) return 0;
  slot = &r->slots[cons & (WIRED_SRVINBOX_DEPTH - 1)];
  if (slot->len > out_cap) return 0;
  quic_memcpy(out_buf, slot->buf, slot->len);
  __atomic_store_n(&r->cons, cons + 1, __ATOMIC_RELEASE);
  return slot->len;
}
