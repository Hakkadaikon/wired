#include "app/http3/core/h3/priority.h"

/* RFC 9218 4.1: defaults are urgency 3, non-incremental. */
void quic_h3_priority_init(quic_h3_priority* p) {
  p->urgency     = QUIC_H3_URGENCY_DEFAULT;
  p->incremental = 0;
}

/* RFC 9218 4.1: a lower urgency value indicates higher priority. */
int quic_h3_priority_higher(u8 urg_a, u8 urg_b) { return urg_a < urg_b; }

/* RFC 9218 4.1: urgency ranges 0..7. */
int quic_h3_urgency_valid(u8 u) { return u <= QUIC_H3_URGENCY_MAX; }

void quic_h3_priority_set_urgency(quic_h3_priority* p, u8 digit) {
  if (digit < '0' || digit > '7') return;
  p->urgency = (u8)(digit - '0');
}

/* 1 when the member at v[i] ends right there (bare key). */
static int sfv_bare(quic_span v, usz i) {
  return i + 1 >= v.n || v.p[i + 1] == ',' || v.p[i + 1] == ' ';
}

/* 1 when v[i..] is `X=?` with a fourth byte to read. */
static int sfv_has_flag(quic_span v, usz i) {
  return i + 3 < v.n && v.p[i + 1] == '=' && v.p[i + 2] == '?';
}

void quic_h3_priority_set_incremental(quic_h3_priority* p, quic_span v, usz i) {
  if (sfv_bare(v, i)) {
    p->incremental = 1;
    return;
  }
  if (sfv_has_flag(v, i)) p->incremental = (u8)(v.p[i + 3] == '1');
}
