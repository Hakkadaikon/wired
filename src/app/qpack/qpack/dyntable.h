#ifndef QPACK_DYNTABLE_H
#define QPACK_DYNTABLE_H

#include "app/qpack/qpack/field.h"

/* RFC 9204 3.2. QPACK dynamic table: inserted (name, value) entries kept
 * back to back in a byte ring the size of the largest capacity the table
 * can be given, so the capacity is the only limit on an entry (3.2.2).
 * Absolute indices grow from 0 with each insert; old entries are evicted
 * when capacity is exceeded. No allocation, no libc. */

/** RFC 9204 3.2.3 / 5: the largest capacity a table holds -- the capacity
 * this server advertises (63 entries of the 32-byte minimum size). A larger
 * requested capacity is clamped to it. */
#define QPACK_DYN_MAX_CAPACITY 2016
/** RFC 9204 3.2.1 / 4.5.1.1: every entry costs at least 32 bytes, so a table
 * within QPACK_DYN_MAX_CAPACITY never holds more entries than this. */
#define QPACK_DYN_MAX_ENTRIES (QPACK_DYN_MAX_CAPACITY / 32)

/** RFC 9204 3.2. Where one live entry's bytes sit in the byte ring: the name
 * starts at off, the value follows it. */
typedef struct {
  u16 off;       /**< byte ring offset of the name's first byte */
  u16 name_len;  /**< name bytes */
  u16 value_len; /**< value bytes, right after the name */
} qpack_dyn_entry;

/** RFC 9204 3.2. A QPACK dynamic table instance: the byte ring, the live
 * entries' positions in it, and the byte-size accounting eviction and
 * capacity changes use. */
typedef struct {
  /** Entry bytes; ring byte i is stored at both i and
   * i + QPACK_DYN_MAX_CAPACITY, so an entry that runs past the ring's end
   * still reads as one contiguous view from its off. */
  u8              bytes[2 * QPACK_DYN_MAX_CAPACITY];
  qpack_dyn_entry ring[QPACK_DYN_MAX_ENTRIES]; /**< live entry positions */
  usz             head;     /**< ring slot of the oldest live entry */
  usz             count;    /**< number of live entries */
  usz             tail;     /**< byte ring offset of the next entry */
  u64             dropped;  /**< absolute index of the oldest live entry */
  usz             size;     /**< sum of entry sizes (RFC 9204 3.2.1) */
  usz             capacity; /**< maximum allowed size in bytes */
  /** RFC 9204 4.5.1.1: the decoder's advertised maximum capacity, the
   * MaxEntries base for Required Insert Count decoding (qpack_dyn_init
   * seeds it with the initial capacity). */
  u64 max_capacity;
} qpack_dyn;

/* RFC 9204 3.2. Initialise an empty table with the given byte capacity
 * (clamped to QPACK_DYN_MAX_CAPACITY). */
void qpack_dyn_init(qpack_dyn* t, usz capacity);

/* RFC 9204 3.2 / 3.2.1. Insert the (name, value) pair, evicting oldest
 * entries as needed to fit. Returns 1 on success, 0 if the entry cannot fit
 * even in an empty table. f must not view this table's own bytes: copy a
 * referenced entry out first, since eviction may reuse them. */
int qpack_dyn_insert(qpack_dyn* t, const qpack_field* f);

/* RFC 9204 3.2. Borrowed views of the live entry `off` places after the
 * oldest (off < t->count); valid until the next insert. */
void qpack_dyn_entry_at(const qpack_dyn* t, usz off, qpack_field* out);

/* RFC 9204 3.2.1. Current total size in bytes. */
usz qpack_dyn_size(const qpack_dyn* t);

/* RFC 9204 3.2.2. Apply a new dynamic table capacity from a received Set
 * Dynamic Table Capacity instruction (Section 4.3.1) once it has already
 * passed qpack_capacity_within_limit: evicts entries from the end of
 * the table until its size is at most new_capacity (a no-op if the
 * capacity is being raised, or set to 0 to clear the table entirely).
 * Clamped to QPACK_DYN_MAX_CAPACITY. */
void qpack_dyn_set_capacity(qpack_dyn* t, usz new_capacity);

/* RFC 9204 4.3.1. A received Set Dynamic Table Capacity instruction's value is
 * valid only up to the limit the server advertised in
 * SETTINGS_QPACK_MAX_TABLE_CAPACITY. Returns 1 if capacity is within that
 * limit, 0 if it exceeds it -- the caller treats 0 as a connection error of
 * type QPACK_ENCODER_STREAM_ERROR. */
int qpack_capacity_within_limit(u64 capacity, u64 max_table_capacity);

#endif
