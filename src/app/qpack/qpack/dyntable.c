#include "app/qpack/qpack/dyntable.h"

/* RFC 9204 3.2.1 */
static usz entry_size(usz name_len, usz value_len) {
  return name_len + value_len + 32;
}

void qpack_dyn_init(qpack_dyn* t, usz capacity) {
  t->head     = 0;
  t->count    = 0;
  t->dropped  = 0;
  t->size     = 0;
  t->capacity = capacity;
}

usz qpack_dyn_size(const qpack_dyn* t) { return t->size; }

/* RFC 9204 3.2.2: drop the oldest entry to reclaim space. */
static void evict_oldest(qpack_dyn* t) {
  qpack_dyn_entry* e = &t->ring[t->head];
  t->size -= entry_size(e->name_len, e->value_len);
  t->head = (t->head + 1) % QUIC_QPACK_DYN_MAX_ENTRIES;
  t->count--;
  t->dropped++;
}

static int fits_fields(const qpack_field* f) {
  return f->name.n <= QUIC_QPACK_DYN_MAX_NAME &&
         f->value.n <= QUIC_QPACK_DYN_MAX_VALUE;
}

static int over_capacity(const qpack_dyn* t, usz need) {
  return t->size + need > t->capacity;
}

/* RFC 9204 3.2.2: evict until the new entry fits or nothing remains. */
static void make_room(qpack_dyn* t, usz need) {
  while (t->count > 0 && over_capacity(t, need)) evict_oldest(t);
}

static int can_insert(const qpack_dyn* t, usz need, const qpack_field* f) {
  if (!fits_fields(f)) return 0;
  if (need > t->capacity) return 0;
  return t->count < QUIC_QPACK_DYN_MAX_ENTRIES;
}

static void copy_field(u8* dst, wired_span src) {
  for (usz i = 0; i < src.n; i++) dst[i] = src.p[i];
}

static void store_entry(qpack_dyn* t, const qpack_field* f) {
  usz              slot = (t->head + t->count) % QUIC_QPACK_DYN_MAX_ENTRIES;
  qpack_dyn_entry* e    = &t->ring[slot];
  copy_field(e->name, f->name);
  copy_field(e->value, f->value);
  e->name_len  = f->name.n;
  e->value_len = f->value.n;
  t->size += entry_size(f->name.n, f->value.n);
  t->count++;
}

int qpack_dyn_insert(qpack_dyn* t, const qpack_field* f) {
  usz need = entry_size(f->name.n, f->value.n);
  if (!can_insert(t, need, f)) return 0;
  make_room(t, need);
  store_entry(t, f);
  return 1;
}

/* RFC 9204 3.2.2: "Whenever the dynamic table capacity is reduced ...
 * entries are evicted from the end of the dynamic table until the size of
 * the dynamic table is less than or equal to the new table capacity." A
 * raise never evicts (make_room's own over_capacity(t, 0) check is
 * size > capacity, so a raised capacity is never "over" and the loop is a
 * no-op) -- both directions share this one path. */
void qpack_dyn_set_capacity(qpack_dyn* t, usz new_capacity) {
  t->capacity = new_capacity;
  make_room(t, 0);
}

/* RFC 9204 4.3.1 */
int qpack_capacity_within_limit(u64 capacity, u64 max_table_capacity) {
  return capacity <= max_table_capacity;
}
