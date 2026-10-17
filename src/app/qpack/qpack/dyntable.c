#include "app/qpack/qpack/dyntable.h"

/* RFC 9204 3.2.1 */
static usz entry_size(usz name_len, usz value_len) {
  return name_len + value_len + 32;
}

static usz clamp_capacity(usz capacity) {
  return capacity < QPACK_DYN_MAX_CAPACITY ? capacity : QPACK_DYN_MAX_CAPACITY;
}

void qpack_dyn_init(qpack_dyn* t, usz capacity) {
  t->head         = 0;
  t->count        = 0;
  t->tail         = 0;
  t->dropped      = 0;
  t->size         = 0;
  t->capacity     = clamp_capacity(capacity);
  t->max_capacity = t->capacity;
}

usz qpack_dyn_size(const qpack_dyn* t) { return t->size; }

/* RFC 9204 3.2.2: drop the oldest entry to reclaim space. */
static void evict_oldest(qpack_dyn* t) {
  qpack_dyn_entry* e = &t->ring[t->head];
  t->size -= entry_size(e->name_len, e->value_len);
  t->head = (t->head + 1) % QPACK_DYN_MAX_ENTRIES;
  t->count--;
  t->dropped++;
}

static int over_capacity(const qpack_dyn* t, usz need) {
  return t->size + need > t->capacity;
}

/* RFC 9204 3.2.2: evict until the new entry fits or nothing remains. Once
 * it fits, the live bytes plus the new entry's stay below the ring's size
 * (each live entry also costs 32 it does not store), so writing at tail
 * never overwrites a live byte, and count stays within
 * QPACK_DYN_MAX_ENTRIES. */
static void make_room(qpack_dyn* t, usz need) {
  while (t->count > 0 && over_capacity(t, need)) {
    evict_oldest(t);
  }
}

/* Write src at the ring's tail, mirrored so it reads back contiguously. */
static void ring_put(qpack_dyn* t, wired_span src) {
  for (usz i = 0; i < src.n; i++) {
    t->bytes[t->tail]                          = src.p[i];
    t->bytes[t->tail + QPACK_DYN_MAX_CAPACITY] = src.p[i];
    t->tail = (t->tail + 1) % QPACK_DYN_MAX_CAPACITY;
  }
}

static void store_entry(qpack_dyn* t, const qpack_field* f) {
  usz              slot = (t->head + t->count) % QPACK_DYN_MAX_ENTRIES;
  qpack_dyn_entry* e    = &t->ring[slot];
  e->off                = (u16)t->tail;
  e->name_len           = (u16)f->name.n;
  e->value_len          = (u16)f->value.n;
  ring_put(t, f->name);
  ring_put(t, f->value);
  t->size += entry_size(f->name.n, f->value.n);
  t->count++;
}

int qpack_dyn_insert(qpack_dyn* t, const qpack_field* f) {
  usz need = entry_size(f->name.n, f->value.n);
  if (need > t->capacity) {
    return 0;
  }
  make_room(t, need);
  store_entry(t, f);
  return 1;
}

void qpack_dyn_entry_at(const qpack_dyn* t, usz off, qpack_field* out) {
  const qpack_dyn_entry* e = &t->ring[(t->head + off) % QPACK_DYN_MAX_ENTRIES];
  const u8*              p = t->bytes + e->off;
  out->name                = wired_span_of(p, e->name_len);
  out->value               = wired_span_of(p + e->name_len, e->value_len);
}

/* RFC 9204 3.2.2: "Whenever the dynamic table capacity is reduced ...
 * entries are evicted from the end of the dynamic table until the size of
 * the dynamic table is less than or equal to the new table capacity." A
 * raise never evicts (make_room's own over_capacity(t, 0) check is
 * size > capacity, so a raised capacity is never "over" and the loop is a
 * no-op) -- both directions share this one path. */
void qpack_dyn_set_capacity(qpack_dyn* t, usz new_capacity) {
  t->capacity = clamp_capacity(new_capacity);
  make_room(t, 0);
}

/* RFC 9204 4.3.1 */
int qpack_capacity_within_limit(u64 capacity, u64 max_table_capacity) {
  return capacity <= max_table_capacity;
}
