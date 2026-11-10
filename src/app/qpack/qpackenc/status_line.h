#ifndef QPACKENC_STATUS_LINE_H
#define QPACKENC_STATUS_LINE_H

#include "app/qpack/qpackenc/qpackenc.h"
#include "common/bytes/span/span.h"

/** @file
 * RFC 9204 4.5 / 4.5.1 / 4.5.2 / 4.5.6. The server response encoder's
 * ":status" field line, dynamic-table aware: an exact static-table match
 * (RFC 9204 App. A) still emits Indexed Field Line T=1 as before; otherwise,
 * when st's capacity allows, the value is inserted into (or already lives
 * in) the encoder-side dynamic table and referenced with Indexed Field Line
 * T=0; only when the dynamic table cannot hold it (including capacity == 0,
 * this server's current advertised default) does it fall back to the prior
 * Literal Field Line behavior. */

/** One :status field line's encode result: the field-line bytes, the
 * Required Insert Count this field SECTION's Prefix must carry (0 unless a
 * dynamic-table reference/insert was used), and the pending encoder-stream
 * instruction to send on the QPACK encoder stream (insert_len == 0 = none
 * this call). */
typedef struct {
  u8  field[64];             /**< the :status field line bytes */
  usz field_len;             /**< bytes at field */
  u64 required_insert_count; /**< RFC 9204 4.5.1: this section's Prefix RIC */
  u8  insert_instr[QPACK_DYN_MAX_CAPACITY + 8];
  usz insert_len; /**< bytes at insert_instr, 0 if none generated */
  u16 status;     /**< the status encoded, for qpackenc_status_commit */
} qpackenc_status_result;

/** Encode one :status field line against st (see qpackenc_plan_field).
 * status is rendered as its 3 decimal ASCII digits (RFC 9110 15) before
 * matching. A planned insert is not applied here: call
 * qpackenc_status_commit once its instruction is staged.
 * @param st the encoder-side state, unchanged
 * @param status the HTTP status code
 * @param out the result, always fully written (every shape produced here,
 *   at most 6 bytes, fits the 64-byte out->field) */
void qpackenc_status_line(
    u16 status, const qpackenc_state* st, qpackenc_status_result* out);

/** RFC 9204 2.1.4: apply r's planned insert to st (qpackenc_commit_field);
 * a no-op when r planned none (insert_len == 0). Call only after the field
 * section was built and r's instruction staged on the encoder stream. */
void qpackenc_status_commit(
    qpackenc_state* st, const qpackenc_status_result* r);

#endif
