#include "tls/ext/stp/parse_tp.h"

#include "common/bytes/varint/varint.h"
#include "tls/ext/tparam/tpblob.h"

/* Decode the value view as a varint into *value (0 if not a single one). */
static void emit_int(quic_span val, u64* value) {
  u64 v = 0;
  if (!value) return;
  quic_varint_decode(val.p, val.n, &v);
  *value = v;
}

/* Fill the caller's out params from a matched value view. */
static void stp_emit(quic_span val, const quic_stp_out* out) {
  emit_int(val, out->value);
  if (out->bytes) *out->bytes = val;
}

/* What quic_stp_parse is looking for, and where to put it. */
typedef struct {
  u64                 param_id;
  const quic_stp_out* out;
} stp_want;

/* Read the TLV at *off, advancing *off past it. Returns 1 if it matched
 * want->param_id (want->out filled), 0 if not, -1 if the TLV is malformed. */
static int step_tlv(quic_span tp, usz* off, const stp_want* want) {
  u64       id;
  quic_span val;
  usz       r =
      quic_tparam_get_blob(quic_span_of(tp.p + *off, tp.n - *off), &id, &val);
  if (r == 0) return -1;
  *off += r;
  if (id != want->param_id) return 0;
  stp_emit(val, want->out);
  return 1;
}

int quic_stp_parse(quic_span tp, u64 param_id, const quic_stp_out* out) {
  usz      off  = 0;
  stp_want want = {param_id, out};
  while (off < tp.n) {
    int s = step_tlv(tp, &off, &want);
    if (s != 0) return s == 1;
  }
  return 0;
}
