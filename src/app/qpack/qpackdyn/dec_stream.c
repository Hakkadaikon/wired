#include "app/qpack/qpackdyn/dec_stream.h"

#include "app/qpack/qpack/instruction.h"
#include "common/bytes/util/bytes.h"

/* RFC 9204 4.4.1 / 2.2.2: a Section Acknowledgment raises the encoder's
 * Known Received Count to the section's Required Insert Count. */
static void raise_acked(qdyn_dec* d, u64 ric) {
  if (ric > d->acked) {
    d->acked = ric;
  }
}

/* Append one instruction to the queue; its length, 0 if it does not fit. */
static usz qdyn_dec_queue(qdyn_dec* d, qpack_dec_kind kind, u64 v) {
  usz n = qpack_dec_instr_encode(
      wired_mspan_of(d->acks + d->acks_len, QDYN_DEC_ACKS_MAX - d->acks_len),
      kind, v);
  d->acks_len += n;
  return n;
}

void qdyn_dec_section_ack(qdyn_dec* d, u64 stream_id, u64 ric) {
  if (ric == 0) {
    return;
  }
  if (qdyn_dec_queue(d, QPACK_DEC_SECTION_ACK, stream_id)) {
    raise_acked(d, ric);
  }
}

void qdyn_dec_stream_cancel(qdyn_dec* d, u64 stream_id) {
  qdyn_dec_queue(d, QPACK_DEC_STREAM_CANCEL, stream_id);
}

/* RFC 9204 4.4.3: the increment for the inserts nothing acknowledged yet
 * (an Increment of 0 is an error, so none is written then). */
static usz put_increment(const qdyn_dec* d, u64 inserts, wired_mspan b) {
  if (inserts <= d->acked) {
    return 0;
  }
  return qpack_dec_instr_encode(b, QPACK_DEC_INSERT_COUNT, inserts - d->acked);
}

usz qdyn_dec_pending(const qdyn_dec* d, u64 inserts, wired_obuf* out) {
  usz n = 0;
  bytes_put(
      wired_mspan_of(out->p, out->cap), &n,
      wired_span_of(d->acks, d->acks_len));
  n += put_increment(d, inserts, wired_mspan_of(out->p + n, out->cap - n));
  out->len = n;
  return n;
}

void qdyn_dec_sent(qdyn_dec* d, u64 inserts) {
  d->acks_len = 0;
  raise_acked(d, inserts);
}
