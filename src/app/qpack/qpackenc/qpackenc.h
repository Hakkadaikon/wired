#ifndef QPACKENC_QPACKENC_H
#define QPACKENC_QPACKENC_H

#include "app/qpack/qpack/dyntable.h"
#include "app/qpack/qpack/field.h"

/** @file
 * RFC 9204 2.1 / 3.2 / 4.3.3 / 4.4. The server's OWN QPACK encoder-side
 * state: the dynamic table it is actively inserting into (mirrors, byte for
 * byte, what it has told the peer's decoder via the encoder stream), plus
 * the Known Received Count / Total Inserts / pending-acknowledgment
 * bookkeeping RFC 9204 2.1.4 requires an encoder to track. Separate from
 * wired_h3srv_state.qdyn, which holds the PEER's encoder-stream instructions
 * applied to THIS endpoint's decoder-side table (RFC 9204 3.2) -- an
 * endpoint's send and receive dynamic tables are independent (9204-006). */

/** One connection's QPACK encoder-side state. */
typedef struct {
  qpack_dyn dyn; /**< the table this encoder inserts into and references */
  u64       total_inserts;  /**< RFC 9204 2.1.4: insertions/duplications sent */
  u64       known_received; /**< RFC 9204 2.1.4: last Known Received Count */
  /** RFC 9204 4.4.1: field sections sent with Required Insert Count > 0
   * that have not yet been acknowledged. */
  u64 pending_acks;
  /** RFC 9204 4.3.1: a Set Dynamic Table Capacity is owed ahead of the next
   * insert (set by qpackenc_peer_capacity). */
  int cap_pending;
} qpackenc_state;

/** The encoder's own table cap: the dyntable storage bound (63 entries of the
 * 32-byte minimum), which every connection already holds whatever the peer
 * allows. Build with -DQPACKENC_LOCAL_CAP=0 to keep responses off
 * the dynamic table. */
#ifndef QPACKENC_LOCAL_CAP
#define QPACKENC_LOCAL_CAP QPACK_DYN_MAX_CAPACITY
#endif
/** RFC 9204 3.2: initialise an empty encoder-side table with the given byte
 * capacity (this server's own SETTINGS_QPACK_MAX_TABLE_CAPACITY) and zeroed
 * counters.
 * @param st the state to initialise
 * @param capacity this server's own advertised dynamic table capacity in
 *   bytes (0 disables dynamic-table use entirely) */
void qpackenc_init(qpackenc_state* st, u64 capacity);

/** RFC 9204 3.2.3 / 5: apply the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY
 * to a still-empty table: capacity min(peer_max, QPACKENC_LOCAL_CAP), with
 * peer_max itself as the MaxTableCapacity Required Insert Count is encoded
 * against (4.5.1.1). A nonzero capacity owes a Set Dynamic Table Capacity
 * (4.3.1), which qpackenc_plan_field puts ahead of the first insert.
 * @param st the encoder-side state, not yet inserted into
 * @param peer_max the peer's advertised maximum table capacity */
void qpackenc_peer_capacity(qpackenc_state* st, u64 peer_max);

/** RFC 9204 4.3.3 / 2.1.2. The outcome of deciding how to encode one field
 * value against the encoder-side dynamic table: a reference to an
 * acknowledged entry (used_dynamic == 1), and/or a fresh insert instruction
 * to send on the encoder stream (insert_len > 0, used_dynamic == 0: the new
 * entry is referenced only once acknowledged), or neither (the caller falls
 * back to a static/literal field line). */
typedef struct {
  /** RFC 9204 4.3.1 + 4.3.3 encoder-stream instruction bytes to send (a
   * pending Set Dynamic Table Capacity, then the insert), or unused
   * (insert_len == 0) when no new insert was generated this call. */
  u8  insert_instr[QPACK_DYN_MAX_CAPACITY + 8];
  usz insert_len; /**< bytes at insert_instr; 0 = no instruction generated */
  /** RFC 9204 3.2.4: absolute index of the referenced entry. Valid only when
   * used_dynamic is 1. */
  u64 abs_index;
  int used_dynamic; /**< 1 = reference the dynamic table, 0 = fall back */
} qpackenc_plan;

/** RFC 9204 2.1 / 4.3.3. Plan how to encode field f against st's dynamic
 * table: if an entry with f's exact (name, value) is live, reference it once
 * the decoder has acknowledged its insert (never before: this encoder treats
 * SETTINGS_QPACK_BLOCKED_STREAMS as 0, RFC 9204 2.1.2); else, when it fits
 * without evicting an entry that is unacknowledged or referenced by an
 * unacknowledged section (2.1.1), generate its Insert With Literal Name
 * instruction. Capacity 0 never inserts or references.
 * @param st the encoder-side state, unchanged: a planned insert takes effect
 *   only through qpackenc_commit_field, once its instruction is sent
 * @param f the (name, value) pair to encode a reference for
 * @param out the plan, always fully written
 * @return 1 always (the plan itself carries the fallback outcome) */
int qpackenc_plan_field(
    const qpackenc_state* st, const qpack_field* f, qpackenc_plan* out);

/** RFC 9204 2.1.4 / 4.3.1: apply a planned insert of f (insert_len > 0) once
 * its instruction is staged on the encoder stream: insert into dyn, count it
 * in total_inserts, and clear the owed Set Dynamic Table Capacity. Keeping
 * this apart from the plan means a field section that is never sent leaves
 * the encoder's table in step with the peer's. */
void qpackenc_commit_field(qpackenc_state* st, const qpack_field* f);

/** RFC 9204 4.4.1: record that a field section referencing the dynamic
 * table (Required Insert Count ric > 0) was just sent -- a no-op when
 * ric == 0 (nothing to acknowledge). Call once per field section built. */
void qpackenc_note_sent(qpackenc_state* st, u64 ric);

/** RFC 9204 4.4.3: apply a received Insert Count Increment. Validates via
 * qpack_incr_valid before applying, so an invalid increment (zero, or one
 * that would push known_received past total_inserts) leaves st unchanged.
 * @return 1 if applied, 0 if increment was invalid (QPACK_DECODER_STREAM_
 *   ERROR territory on the caller's side) */
int qpackenc_on_increment(qpackenc_state* st, u64 increment);

/** RFC 9204 4.4.1: apply a received Section Acknowledgment. Validates via
 * qpack_section_ack_valid before applying, so an acknowledgment with no
 * pending field section left unchanged.
 * @return 1 if applied (pending_acks decremented), 0 if invalid
 *   (QPACK_DECODER_STREAM_ERROR territory on the caller's side) */
int qpackenc_on_section_ack(qpackenc_state* st);

/** Longest decoder instruction held whole: a prefix byte plus the ten
 * continuation bytes a 62-bit integer can need (RFC 9204 4.1.1). */
#define QPACKENC_DECRX_PART 11

/** RFC 9204 4.2 / 4.4: the peer's decoder stream, read in stream order.
 * Zero-initialise. */
typedef struct {
  u64 stream_id; /**< the peer's decoder stream (0: none seen yet) */
  u64 off;       /**< next stream offset to read */
  u8  part[QPACKENC_DECRX_PART]; /**< an instruction's bytes so far */
  usz part_len;                  /**< bytes used in part */
} qpackenc_decrx;

/** Start reading stream_id as the peer's decoder stream, past its type
 * varint of type_len bytes. */
void qpackenc_decrx_take(qpackenc_decrx* rx, u64 stream_id, u64 type_len);

/** RFC 9204 4.4: apply the decoder instructions in d (at stream offset
 * off of rx's stream) to st: Section Acknowledgment (4.4.1), Stream
 * Cancellation (4.4.2), Insert Count Increment (4.4.3). Bytes already read
 * are skipped. shortcut: a frame past a gap (reordered ahead of an earlier
 * one) is dropped, and since the transport acknowledged it, reading stops at
 * that gap for good -- never a false error; a reassembly window like
 * qdyn_encrx's once a reordering peer's acknowledgments must be checked.
 * @return 1 ok, 0 on an invalid instruction (an acknowledgment of nothing
 *   pending, an increment of 0 or past the inserts sent, an overlong
 *   integer): QPACK_DECODER_STREAM_ERROR */
int qpackenc_decrx_feed(
    qpackenc_decrx* rx, qpackenc_state* st, u64 off, wired_span d);

#endif
