#include "tls/ext/tparam/tpcheck.h"

#include "tls/ext/tparam/tparam.h"

/* Whether the first n bytes of a and b are equal. */
static int bytes_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

int quic_tparam_cid_match(quic_span got, quic_span expected) {
  if (got.n != expected.n) return 0;
  return bytes_eq(got.p, expected.p, got.n);
}

int quic_tparam_check_initial_scid(quic_span got, quic_span observed) {
  return quic_tparam_cid_match(got, observed);
}

int quic_tparam_check_original_dcid(quic_span got, quic_span sent_dcid) {
  return quic_tparam_cid_match(got, sent_dcid);
}

int quic_tparam_check_retry_scid(const quic_tparam_retry_scid_in* in) {
  if (in->did_retry != in->has_param)
    return 0;                   /* present iff a Retry was processed */
  if (!in->did_retry) return 1; /* both absent: nothing to match */
  return quic_tparam_cid_match(in->got, in->retry_scid);
}

/* RFC 9000 18.2 range-constrained parameters: id, inclusive minimum,
 * inclusive maximum (U64_MAX means unbounded above). */
typedef struct {
  u64 id, min, max;
} tp_range_row;

static const tp_range_row tp_range[] = {
    {QUIC_TP_MAX_UDP_PAYLOAD_SIZE, 1200, 0xffffffffffffffffull},
    {QUIC_TP_ACK_DELAY_EXPONENT, 0, 20},
    {QUIC_TP_MAX_ACK_DELAY, 0, 16383},
    {QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 2, 0xffffffffffffffffull},
};

/* The range row for id, or 0 if id carries no range constraint. */
static const tp_range_row* range_row(u64 id) {
  for (usz i = 0; i < sizeof(tp_range) / sizeof(tp_range[0]); i++)
    if (tp_range[i].id == id) return &tp_range[i];
  return 0;
}

int quic_tparam_range_ok(u64 id, u64 value) {
  const tp_range_row* row = range_row(id);
  if (!row) return 1; /* no constraint on this parameter */
  return value >= row->min && value <= row->max;
}
