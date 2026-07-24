#ifndef QUIC_QPACK_DYNTABLE_H
#define QUIC_QPACK_DYNTABLE_H

#include "app/qpack/qpack/field.h"

/* RFC 9204 3.2. QPACK dynamic table: a fixed-capacity ring of inserted
 * (name, value) entries. Absolute indices grow from 0 with each insert; old
 * entries are evicted when capacity is exceeded. Names and values are stored
 * inline with fixed per-field upper bounds (no allocation, no libc). */

#define QUIC_QPACK_DYN_MAX_ENTRIES 64
#define QUIC_QPACK_DYN_MAX_NAME 256
#define QUIC_QPACK_DYN_MAX_VALUE 1024

typedef struct {
  u8  name[QUIC_QPACK_DYN_MAX_NAME];
  u8  value[QUIC_QPACK_DYN_MAX_VALUE];
  usz name_len;
  usz value_len;
} quic_qpack_dyn_entry;

typedef struct {
  quic_qpack_dyn_entry ring[QUIC_QPACK_DYN_MAX_ENTRIES];
  usz                  head;     /* physical slot of the oldest live entry */
  usz                  count;    /* number of live entries */
  u64                  dropped;  /* absolute index of the oldest live entry */
  usz                  size;     /* sum of entry sizes (RFC 9204 3.2.1) */
  usz                  capacity; /* maximum allowed size in bytes */
} quic_qpack_dyn;

/* RFC 9204 3.2. Initialise an empty table with the given byte capacity. */
void quic_qpack_dyn_init(quic_qpack_dyn* t, usz capacity);

/* RFC 9204 3.2 / 3.2.1. Insert the (name, value) pair, evicting oldest
 * entries as needed to fit. Returns 1 on success, 0 if the entry cannot fit
 * even in an empty table or exceeds the inline field bounds. */
int quic_qpack_dyn_insert(quic_qpack_dyn* t, const quic_qpack_field* f);

/* RFC 9204 3.2.1. Current total size in bytes. */
usz quic_qpack_dyn_size(const quic_qpack_dyn* t);

/* RFC 9204 4.3.1. A received Set Dynamic Table Capacity instruction's value is
 * valid only up to the limit the server advertised in
 * SETTINGS_QPACK_MAX_TABLE_CAPACITY. Returns 1 if capacity is within that
 * limit, 0 if it exceeds it -- the caller treats 0 as a connection error of
 * type QPACK_ENCODER_STREAM_ERROR. */
int quic_qpack_capacity_within_limit(u64 capacity, u64 max_table_capacity);

#endif
