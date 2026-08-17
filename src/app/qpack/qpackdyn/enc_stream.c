#include "app/qpack/qpackdyn/enc_stream.h"

#include "app/qpack/qpack/error.h"
#include "app/qpack/qpack/instruction.h"

/* RFC 9204 4.3.1 / 5 (9204-032): apply a decoded Set Dynamic Table Capacity
 * value, rejecting one that exceeds the server's own advertised limit. */
static usz apply_capacity(
    qpack_dyn* t, u64 capacity, u64 max_table_capacity, u16* err) {
  if (!qpack_capacity_within_limit(capacity, max_table_capacity)) {
    *err = QPACK_ENCODER_STREAM_ERROR;
    return 0;
  }
  qpack_dyn_set_capacity(t, (usz)capacity);
  return 1;
}

/* 1 if the decoded instruction is a Set Dynamic Table Capacity (used != 0,
 * kind matches) -- split out so qdyn_enc_apply_capacity's own branch
 * count stays at the CCN gate. */
static int is_set_capacity(usz used, qpack_enc_kind kind) {
  return used != 0 && kind == QPACK_ENC_SET_CAPACITY;
}

usz qdyn_enc_apply_capacity(
    wired_span buf, qpack_dyn* t, u64 max_table_capacity, u16* err) {
  qpack_enc_kind kind;
  u64            value;
  usz            used = qpack_enc_instr_decode(buf, &kind, &value);
  if (!is_set_capacity(used, kind)) return 0;
  if (!apply_capacity(t, value, max_table_capacity, err)) return 0;
  return used;
}
