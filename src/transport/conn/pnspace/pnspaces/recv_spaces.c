#include "transport/conn/pnspace/pnspaces/recv_spaces.h"

#include "transport/recovery/detect/ackgen/ackrange.h"

void pnspaces_recv_init(pnspaces_recv* s) {
  for (int i = 0; i < PNS_COUNT; i++) recvpn_init(&s->r[i]);
}

void pnspaces_on_recv(pnspaces_recv* s, int space, u64 pn) {
  recvpn_record(&s->r[space], pn);
}

/* Collect received PNs in `r` into out ascending (lowest first), returning the
 * count. At most PNSPACES_ACK_CAP entries: the window below largest, then
 * largest itself. */
static usz collect_pns(const recvpn* r, u64* out) {
  usz n = 0;
  for (u64 d = RECVPN_WINDOW; d >= 1; d--)
    if (recvpn_seen(r, r->largest - d)) out[n++] = r->largest - d;
  out[n++] = r->largest;
  return n;
}

int pnspaces_ack_ranges(
    const pnspaces_recv* s, int space, const pnspaces_ack_out* out) {
  u64           pns[PNSPACES_ACK_CAP];
  const recvpn* r = &s->r[space];
  if (!r->any) return 0;
  return ackgen_build_ranges(
      (u64view){pns, collect_pns(r, pns)}, out->largest, out->ranges);
}
