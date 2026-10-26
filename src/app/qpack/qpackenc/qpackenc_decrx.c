#include "app/qpack/qpack/instruction.h"
#include "app/qpack/qpackenc/qpackenc.h"

static int decrx_ack(qpackenc_state* st, u64 stream_id) {
  (void)stream_id;
  return qpackenc_on_section_ack(st);
}

/* RFC 9204 4.4.2: this encoder never references its table, so a cancelled
 * stream releases no entry; the instruction is always valid. */
static int decrx_cancel(qpackenc_state* st, u64 stream_id) {
  (void)st;
  (void)stream_id;
  return 1;
}

static int (*const decrx_apply[3])(qpackenc_state*, u64) = {
    [QPACK_DEC_SECTION_ACK]   = decrx_ack,
    [QPACK_DEC_STREAM_CANCEL] = decrx_cancel,
    [QPACK_DEC_INSERT_COUNT]  = qpackenc_on_increment,
};

void qpackenc_decrx_take(qpackenc_decrx* rx, u64 stream_id, u64 type_len) {
  rx->stream_id = stream_id;
  rx->off       = type_len;
  rx->part_len  = 0;
}

/* Read one more stream byte b; 0 iff it completes an invalid instruction
 * or makes one longer than any valid one. */
static int decrx_byte(qpackenc_decrx* rx, qpackenc_state* st, u8 b) {
  qpack_dec_kind kind;
  u64            v;
  rx->part[rx->part_len++] = b;
  rx->off++;
  if (!qpack_dec_instr_decode(
          wired_span_of(rx->part, rx->part_len), &kind, &v)) {
    return rx->part_len < sizeof rx->part;
  }
  rx->part_len = 0;
  return decrx_apply[kind](st, v);
}

static int decrx_bytes(
    qpackenc_decrx* rx, qpackenc_state* st, wired_span d, u64 skip) {
  for (u64 i = skip; i < d.n; i++) {
    if (!decrx_byte(rx, st, d.p[i])) {
      return 0;
    }
  }
  return 1;
}

int qpackenc_decrx_feed(
    qpackenc_decrx* rx, qpackenc_state* st, u64 off, wired_span d) {
  if (off > rx->off) {
    return 1; /* past a gap: see the shortcut in qpackenc.h */
  }
  return decrx_bytes(rx, st, d, rx->off - off);
}
