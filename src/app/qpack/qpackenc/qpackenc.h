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
} qpackenc_state;

/** RFC 9204 3.2: initialise an empty encoder-side table with the given byte
 * capacity (this server's own SETTINGS_QPACK_MAX_TABLE_CAPACITY) and zeroed
 * counters.
 * @param st the state to initialise
 * @param capacity this server's own advertised dynamic table capacity in
 *   bytes (0 disables dynamic-table use entirely) */
void qpackenc_init(qpackenc_state* st, u64 capacity);

/** RFC 9204 4.3.3 / 3.2.5. The outcome of deciding how to encode one field
 * value against the encoder-side dynamic table: either a fresh insert
 * instruction to send on the encoder stream (insert_len > 0), a reference to
 * an entry already present (insert_len == 0, used_dynamic == 1), or neither
 * (used_dynamic == 0, the caller must fall back to a static/literal field
 * line). */
typedef struct {
  /** RFC 9204 4.3.3 encoder-stream instruction bytes to send, or unused
   * (insert_len == 0) when no new insert was generated this call. */
  u8  insert_instr[QPACK_DYN_MAX_NAME + QPACK_DYN_MAX_VALUE + 8];
  usz insert_len; /**< bytes at insert_instr; 0 = no instruction generated */
  /** RFC 9204 3.2.5: relative index to reference the entry with in the
   * SAME field section this plan is for (Base == total_inserts after this
   * call, i.e. one past the newest live entry). Valid only when
   * used_dynamic is 1. */
  u64 field_rel_index;
  int used_dynamic; /**< 1 = reference the dynamic table, 0 = fall back */
} qpackenc_plan;

/** RFC 9204 2.1 / 4.3.3. Plan how to encode field f against st's dynamic
 * table: if an entry with f's exact (name, value) is already live, reference
 * it (no new instruction); else, if st's capacity allows the entry to fit,
 * insert it (qpack_dyn_insert), generate its Insert With Literal Name
 * instruction (qdyn_insert_literal) and advance total_inserts; else leave
 * used_dynamic 0 so the caller falls back to a static/literal field line
 * (this happens whenever capacity is 0, keeping the pre-existing
 * static-or-literal behavior for the default advertised capacity).
 * @param st the encoder-side state; dyn and total_inserts are updated on a
 *   fresh insert
 * @param f the (name, value) pair to encode a reference for
 * @param out the plan, always fully written
 * @return 1 always (the plan itself carries the fallback outcome) */
int qpackenc_plan_field(
    qpackenc_state* st, const qpack_field* f, qpackenc_plan* out);

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

#endif
