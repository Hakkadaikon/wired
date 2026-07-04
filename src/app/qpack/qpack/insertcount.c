#include "app/qpack/qpack/insertcount.h"

/* RFC 9204 4.5.1.1 */
u64 quic_qpack_ric_encode(u64 ric, u64 max_entries) {
  if (ric == 0) return 0;
  return (ric % (2 * max_entries)) + 1;
}

/* The candidate Required Insert Count before the wrap correction (RFC 9204
 * 4.5.1.1). */
static u64 ric_candidate(u64 encoded, u64 full_range, u64 max_value) {
  u64 max_wrapped = (max_value / full_range) * full_range;
  return max_wrapped + encoded - 1;
}

/* Apply the single wrap correction: if the candidate overshoots max_value it is
 * one full range too high (RFC 9204 4.5.1.1). Returns 0 if it cannot be
 * corrected. */
static int ric_correct(u64* ric, u64 max_value, u64 full_range) {
  if (*ric <= max_value) return 1;
  if (*ric <= full_range) return 0;
  *ric -= full_range;
  return 1;
}

/* Resolve a non-zero EncodedInsertCount to its Required Insert Count (RFC 9204
 * 4.5.1.1). Returns 0 if the encoding is invalid. */
static int ric_resolve(u64 encoded, const quic_qpack_ric_ctx* c, u64* ric) {
  u64 full_range = 2 * c->max_entries;
  u64 max_value  = c->total_inserts + c->max_entries;
  if (encoded > full_range) return 0;
  *ric = ric_candidate(encoded, full_range, max_value);
  if (!ric_correct(ric, max_value, full_range)) return 0;
  return *ric != 0;
}

/* RFC 9204 4.5.1.1 */
int quic_qpack_ric_decode(u64 encoded, const quic_qpack_ric_ctx* c, u64* ric) {
  if (encoded == 0) {
    *ric = 0;
    return 1;
  }
  return ric_resolve(encoded, c, ric);
}
