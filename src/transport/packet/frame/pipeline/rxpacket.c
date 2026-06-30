#include "transport/packet/frame/pipeline/rxpacket.h"

#include "transport/packet/build/vpn/vpn_open.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"

/* RFC 9000 17.2 / RFC 9001 5.4: parse the complete long header to find the
 * packet-number offset and Length, then remove header protection (which
 * reveals the packet-number length) and AEAD-open the payload in place.
 * is_initial selects whether a Token field is present. */
int quic_rx_packet(
    const quic_initial_keys *keys,
    const quic_aes128       *hp,
    u8                      *pkt,
    usz                      pkt_len,
    int                      is_initial,
    const u8               **frames,
    usz                     *frames_len) {
  const u8 *dcid, *scid, *token;
  u8        dcid_len, scid_len;
  usz       token_len, pn_off;
  u64       length;
  if (!quic_lhdr_parse(
          pkt, pkt_len, is_initial, &dcid, &dcid_len, &scid, &scid_len, &token,
          &token_len, &length, &pn_off))
    return 0;
  return quic_vpn_open(
      keys, hp, pkt, pkt_len, pn_off, length, frames, frames_len);
}
