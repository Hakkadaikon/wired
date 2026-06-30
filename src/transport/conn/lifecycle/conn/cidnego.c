#include "transport/conn/lifecycle/conn/cidnego.h"

/* RFC 9000 7.2 */
int quic_cidnego_peer_dcid(
    const u8 *peer_scid, usz scid_len, u8 *our_dcid, usz *our_dcid_len) {
  if (scid_len > 20) return 0;
  for (usz i = 0; i < scid_len; i++) our_dcid[i] = peer_scid[i];
  *our_dcid_len = scid_len;
  return 1;
}

/* RFC 9000 7.2 */
int quic_cidnego_match(const u8 *a, usz a_len, const u8 *b, usz b_len) {
  usz n  = a_len < b_len ? a_len : b_len;
  int eq = (a_len == b_len);
  for (usz i = 0; i < n; i++) eq &= (a[i] == b[i]);
  return eq;
}
