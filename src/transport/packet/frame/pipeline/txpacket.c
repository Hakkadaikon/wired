#include "transport/packet/frame/pipeline/txpacket.h"

#include "transport/packet/header/lhdr/lhdr_build.h"
#include "transport/packet/header/packet/header.h"

/* RFC 9000 17.2: assemble a complete long header (Initial 17.2.2 with Token, or
 * Handshake 17.2.4 without), then protect. pn_len is fixed at 4 (byte0's low
 * bits are forced to agree). */
#define QUIC_TX_PN_LEN 4u

usz quic_tx_packet(
    const quic_protect_keys *k, const quic_tx_desc *d, quic_mspan out) {
  u8             hdr[64 + 2 * WIRED_MAX_CID_LEN];
  usz            len_off = 0;
  quic_obuf      ho      = quic_obuf_of(hdr, sizeof(hdr));
  quic_lhdr_desc h       = {d->byte0,      1,        d->dcid,     d->scid,
                            d->is_initial, d->token, d->frames.n, d->pn,
                            QUIC_TX_PN_LEN};
  if (quic_lhdr_build(&h, &ho, &len_off) == 0) return 0;
  quic_protect_seal_io io = {
      quic_span_of(hdr, ho.len),
      ho.len - QUIC_TX_PN_LEN,
      QUIC_TX_PN_LEN,
      d->pn,
      d->frames,
      out};
  return quic_protect_seal(k, &io);
}
