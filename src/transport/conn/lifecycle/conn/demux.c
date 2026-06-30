#include "transport/conn/lifecycle/conn/demux.h"

int quic_demux_match(
    const u8 *dcid, usz dcid_len, const u8 *conn_cid, usz cid_len) {
  if (dcid_len != cid_len) return 0;
  u8 diff = 0;
  for (usz i = 0; i < dcid_len; i++) diff |= (u8)(dcid[i] ^ conn_cid[i]);
  return diff == 0;
}
