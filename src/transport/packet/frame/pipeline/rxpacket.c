#include "transport/packet/frame/pipeline/rxpacket.h"

#include "transport/packet/build/vpn/vpn_open.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"

/* RFC 9000 17.2 / RFC 9001 5.4: parse the complete long header to find the
 * packet-number offset and Length, then remove header protection (which
 * reveals the packet-number length) and AEAD-open the payload in place. */
int quic_rx_packet(
    const quic_protect_keys *k, const quic_rx_desc *d, quic_span *frames) {
  quic_lhdr h;
  if (!quic_lhdr_parse(quic_span_of(d->pkt.p, d->pkt.n), d->is_initial, &h))
    return 0;
  quic_vpn_desc v = {d->pkt, h.pn_off, h.length};
  return quic_vpn_open(k, &v, frames);
}
