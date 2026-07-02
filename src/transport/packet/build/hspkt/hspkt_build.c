#include "transport/packet/build/hspkt/hspkt_build.h"

#include "transport/packet/frame/pipeline/txpacket.h"

/* RFC 9000 17.2.4: byte0 long-header form (0x80), fixed bit (0x40), type bits
 * 5-4 = Handshake (0x2), and a 4-byte packet-number length (low bits 0x03). */
#define QUIC_HSPKT_BYTE0 0xe3

/* RFC 9000 17.2.4: emit a complete Handshake long header carrying the SCID and
 * no Token field. */
int quic_hspkt_build(
    const quic_protect_keys *k, const quic_hspkt_desc *d, quic_obuf *out) {
  quic_tx_desc t     = {QUIC_HSPKT_BYTE0,   d->dcid, d->scid,   0,
                        quic_span_of(0, 0), d->pn,   d->payload};
  usz          total = quic_tx_packet(k, &t, quic_mspan_of(out->p, out->cap));
  if (total == 0) return 0;
  out->len = total;
  return 1;
}
