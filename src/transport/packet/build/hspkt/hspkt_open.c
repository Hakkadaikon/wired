#include "transport/packet/build/hspkt/hspkt_open.h"

#include "transport/packet/build/vpn/vpn_open.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"

/* RFC 9000 17.2.4 / RFC 9001 5.4: parse the complete Handshake long header
 * (no Token) for the packet-number offset and Length, then remove header
 * protection and AEAD-open the payload in place. */
int quic_hspkt_open(
    const quic_protect_keys* k, quic_mspan pkt, quic_span* payload) {
  quic_lhdr h;
  if (!quic_lhdr_parse(quic_span_of(pkt.p, pkt.n), 0, &h)) return 0;
  quic_vpn_desc d = {pkt, h.pn_off, h.length};
  return quic_vpn_open(k, &d, payload);
}
