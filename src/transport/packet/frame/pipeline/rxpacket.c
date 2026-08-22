#include "transport/packet/frame/pipeline/rxpacket.h"

#include "transport/packet/build/vpn/vpn_open.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"

/* RFC 9000 17.2 / RFC 9001 5.4: parse the complete long header to find the
 * packet-number offset and Length, then remove header protection (which
 * reveals the packet-number length) and AEAD-open the payload in place. */
int rx_packet(const protect_keys* k, const rx_desc* d, wired_span* frames) {
  lhdr h;
  if (!lhdr_parse(wired_span_of(d->pkt.p, d->pkt.n), d->is_initial, &h))
    return 0;
  vpn_desc v = {d->pkt, h.pn_off, h.length, d->largest_pn};
  return vpn_open(k, &v, frames);
}
