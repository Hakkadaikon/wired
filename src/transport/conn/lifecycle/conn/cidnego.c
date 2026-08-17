#include "transport/conn/lifecycle/conn/cidnego.h"

/* RFC 9000 7.2 */
int quic_cidnego_peer_dcid(wired_span peer_scid, wired_obuf* our_dcid) {
  if (peer_scid.n > 20) return 0;
  for (usz i = 0; i < peer_scid.n; i++) our_dcid->p[i] = peer_scid.p[i];
  our_dcid->len = peer_scid.n;
  return 1;
}

/* RFC 9000 7.2 */
int quic_cidnego_match(wired_span a, wired_span b) {
  usz n  = a.n < b.n ? a.n : b.n;
  int eq = (a.n == b.n);
  for (usz i = 0; i < n; i++) eq &= (a.p[i] == b.p[i]);
  return eq;
}
