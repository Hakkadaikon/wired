#include "transport/io/xdp/xskring/xskring.h"

void xskring_init(xskring* r, const xskring_view* v) {
  r->producer    = v->producer;
  r->consumer    = v->consumer;
  r->desc        = v->desc;
  r->size        = v->size;
  r->mask        = v->size - 1;
  r->cached_prod = __atomic_load_n(v->producer, __ATOMIC_ACQUIRE);
  r->cached_cons = __atomic_load_n(v->consumer, __ATOMIC_ACQUIRE);
}

/* Free slots the producer may still write, per the last-known consumer
 * position (cached_cons). */
static u32 xskring_free(const xskring* r) {
  return r->size - (r->cached_prod - r->cached_cons);
}

/* Slots already published by the producer, per the last-known producer
 * position (cached_prod), not yet consumed. */
static u32 xskring_avail(const xskring* r) {
  return r->cached_prod - r->cached_cons;
}

/* Re-read the consumer index (ACQUIRE) so a stale cache can catch up with
 * slots the consumer released concurrently. */
static void xskring_reload_cons(xskring* r) {
  r->cached_cons = __atomic_load_n(r->consumer, __ATOMIC_ACQUIRE);
}

/* Re-read the producer index (ACQUIRE) so a stale cache can catch up with
 * slots the producer published concurrently. */
static void xskring_reload_prod(xskring* r) {
  r->cached_prod = __atomic_load_n(r->producer, __ATOMIC_ACQUIRE);
}

u32 xskring_prod_reserve(xskring* r, u32 n, u32* idx) {
  if (xskring_free(r) < n) xskring_reload_cons(r);
  u32 free    = xskring_free(r);
  u32 granted = free < n ? free : n;
  *idx        = r->cached_prod;
  return granted;
}

void xskring_prod_submit(xskring* r, u32 n) {
  r->cached_prod += n;
  __atomic_store_n(r->producer, r->cached_prod, __ATOMIC_RELEASE);
}

u32 xskring_cons_peek(xskring* r, u32 n, u32* idx) {
  if (xskring_avail(r) < n) xskring_reload_prod(r);
  u32 avail   = xskring_avail(r);
  u32 granted = avail < n ? avail : n;
  *idx        = r->cached_cons;
  return granted;
}

void xskring_cons_release(xskring* r, u32 n) {
  r->cached_cons += n;
  __atomic_store_n(r->consumer, r->cached_cons, __ATOMIC_RELEASE);
}

u64* xskring_addr_at(xskring* r, u32 idx) {
  return &((u64*)r->desc)[idx & r->mask];
}

xdp_desc* xskring_desc_at(xskring* r, u32 idx) {
  return &((xdp_desc*)r->desc)[idx & r->mask];
}
