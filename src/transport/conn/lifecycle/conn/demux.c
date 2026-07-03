#include "transport/conn/lifecycle/conn/demux.h"

int quic_demux_match(quic_span dcid, quic_span conn_cid) {
  if (dcid.n != conn_cid.n) return 0;
  u8 diff = 0;
  for (usz i = 0; i < dcid.n; i++) diff |= (u8)(dcid.p[i] ^ conn_cid.p[i]);
  return diff == 0;
}
