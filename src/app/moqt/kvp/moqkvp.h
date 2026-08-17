#ifndef QUIC_MOQKVP_H
#define QUIC_MOQKVP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * draft-ietf-moq-transport-19 1.4.3 Key-Value-Pair codec.
 *
 * Wire format:
 *   Delta Type (vi64)   -- MOQT varint; Type = previous Type + Delta (0 if
 *                          no previous Type)
 *   [Length (vi64)]     -- present only when Type is odd; value byte count
 *   Value (..)          -- one varint when Type is even, else Length bytes
 *
 * The pair list's cumulative Type MUST NOT exceed 2^64-1 and Length MUST
 * NOT exceed 2^16-1; either is a protocol violation. The codec is a pure
 * cursor pair (take/put); the caller loops over a known byte-bounded list
 * and maps the two error kinds to its close codes.
 */

/** Maximum Value length in bytes for an odd (length-prefixed) Type
 * (draft-ietf-moq-transport-19 1.4.3: 2^16-1). */
#define QUIC_MOQKVP_MAX_LEN 0xFFFF

/** quic_moqkvp_take results. INSUFFICIENT means the input ended mid-pair
 * (may be benign if more bytes can still arrive); VIOLATION means the pair
 * itself is illegal (Type overflow or Length > QUIC_MOQKVP_MAX_LEN) and no
 * amount of further input can fix it. Callers close with different codes. */
#define QUIC_MOQKVP_OK 1
#define QUIC_MOQKVP_INSUFFICIENT 0
#define QUIC_MOQKVP_VIOLATION (-1)

/** One decoded (or to-be-encoded) Key-Value-Pair. */
typedef struct {
  u64        type;   /**< absolute Type (Delta already accumulated) */
  int        is_raw; /**< 1 when type is odd: value in raw; 0: value in num */
  u64        num;    /**< even-Type value (single varint) */
  wired_span raw;    /**< odd-Type value; a view into the decode input */
} quic_moqkvp;

/** Decode the next Key-Value-Pair at *off within buf.
 *
 * On QUIC_MOQKVP_OK, advances *off past the pair, updates *prev_type to
 * the decoded absolute Type (feed the same variable, initialized to 0, to
 * every take of one list), and fills *out (out->raw borrows buf). On any
 * other return, *off and *prev_type are left unmodified.
 *
 * @param buf       bounded input (never reads past buf.n)
 * @param off       in/out cursor within buf
 * @param prev_type in/out cumulative Type (0 before the first pair)
 * @param out       decoded pair on success
 * @return QUIC_MOQKVP_OK, QUIC_MOQKVP_INSUFFICIENT (truncated), or
 *   QUIC_MOQKVP_VIOLATION (Type overflow / Length too large)
 */
int quic_moqkvp_take(
    wired_span buf, usz* off, u64* prev_type, quic_moqkvp* out);

/** Encode one Key-Value-Pair at *off within buf.
 *
 * Encodes kv->type as a minimal-length Delta from *prev_type, then the
 * value from kv->num (even type) or kv->raw (odd type); kv->is_raw is
 * ignored (parity of kv->type decides). On success advances *off and sets
 * *prev_type = kv->type; on failure both are left unmodified.
 *
 * @param buf       destination buffer
 * @param off       in/out cursor within buf
 * @param prev_type in/out cumulative Type (0 before the first pair)
 * @param kv        pair to encode
 * @return 1 ok, 0 if kv->type < *prev_type, kv->raw.n exceeds
 *   QUIC_MOQKVP_MAX_LEN, or buf has no room
 */
int quic_moqkvp_put(
    wired_mspan buf, usz* off, u64* prev_type, const quic_moqkvp* kv);

#endif
