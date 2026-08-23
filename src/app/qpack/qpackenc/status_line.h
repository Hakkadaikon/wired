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
  u8  insert_instr[QPACK_DYN_MAX_NAME + QPACK_DYN_MAX_VALUE + 8];
  usz insert_len; /**< bytes at insert_instr, 0 if none generated */
} qpackenc_status_result;

/** Encode one :status field line against st, updating st's dynamic table and
 * counters on a fresh insert (see qpackenc_plan_field). status is rendered
 * as its 3 decimal ASCII digits (RFC 9110 15) before matching/inserting.
 * @param st the encoder-side state (unchanged on the static-match/literal-
 *   fallback paths)
 * @param status the HTTP status code
 * @param out the result, always fully written
 * @return 1 ok, 0 if out->field lacks capacity (never happens for the
 *   64-byte-bounded shapes produced here in practice, checked all the same) */
int qpackenc_status_line(
    u16 status, qpackenc_state* st, qpackenc_status_result* out);

#endif
