#include "app/qpack/qpack/dyntable.h"

/* RFC 9204 3.2.1 */
static usz entry_size(usz name_len, usz value_len) {
  return name_len + value_len + 32;
}

void quic_qpack_dyn_init(quic_qpack_dyn *t, usz capacity) {
  t->head     = 0;
  t->count    = 0;
  t->dropped  = 0;
  t->size     = 0;
  t->capacity = capacity;
}

usz quic_qpack_dyn_size(const quic_qpack_dyn *t) { return t->size; }

/* RFC 9204 3.2.2: drop the oldest entry to reclaim space. */
static void evict_oldest(quic_qpack_dyn *t) {
  quic_qpack_dyn_entry *e = &t->ring[t->head];
  t->size -= entry_size(e->name_len, e->value_len);
  t->head = (t->head + 1) % QUIC_QPACK_DYN_MAX_ENTRIES;
  t->count--;
  t->dropped++;
}

static int fits_fields(usz name_len, usz value_len) {
  return name_len <= QUIC_QPACK_DYN_MAX_NAME &&
         value_len <= QUIC_QPACK_DYN_MAX_VALUE;
}

static int over_capacity(const quic_qpack_dyn *t, usz need) {
  return t->size + need > t->capacity;
}

/* RFC 9204 3.2.2: evict until the new entry fits or nothing remains. */
static void make_room(quic_qpack_dyn *t, usz need) {
  while (t->count > 0 && over_capacity(t, need)) evict_oldest(t);
}

static int can_insert(
    const quic_qpack_dyn *t, usz need, usz name_len, usz value_len) {
  if (!fits_fields(name_len, value_len)) return 0;
  if (need > t->capacity) return 0;
  return t->count < QUIC_QPACK_DYN_MAX_ENTRIES;
}

static void copy_field(u8 *dst, const u8 *src, usz n) {
  for (usz i = 0; i < n; i++) dst[i] = src[i];
}

static void store_entry(
    quic_qpack_dyn *t,
    const u8       *name,
    usz             name_len,
    const u8       *value,
    usz             value_len) {
  usz slot                = (t->head + t->count) % QUIC_QPACK_DYN_MAX_ENTRIES;
  quic_qpack_dyn_entry *e = &t->ring[slot];
  copy_field(e->name, name, name_len);
  copy_field(e->value, value, value_len);
  e->name_len  = name_len;
  e->value_len = value_len;
  t->size += entry_size(name_len, value_len);
  t->count++;
}

int quic_qpack_dyn_insert(
    quic_qpack_dyn *t,
    const u8       *name,
    usz             name_len,
    const u8       *value,
    usz             value_len) {
  usz need = entry_size(name_len, value_len);
  if (!can_insert(t, need, name_len, value_len)) return 0;
  make_room(t, need);
  store_entry(t, name, name_len, value, value_len);
  return 1;
}
