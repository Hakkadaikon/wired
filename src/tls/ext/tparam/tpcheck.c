#include "tls/ext/tparam/tpcheck.h"

/* Whether the first n bytes of a and b are equal. */
static int bytes_eq(const u8 *a, const u8 *b, usz n) {
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

int quic_tparam_check_retry_scid(const quic_tparam_retry_scid_in *in) {
  if (in->did_retry != in->has_param)
    return 0;                   /* present iff a Retry was processed */
  if (!in->did_retry) return 1; /* both absent: nothing to match */
  return quic_tparam_cid_match(in->got, in->retry_scid);
}
