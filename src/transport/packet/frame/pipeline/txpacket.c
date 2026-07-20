#include "transport/packet/frame/pipeline/txpacket.h"

#include "transport/packet/header/lhdr/lhdr_build.h"
#include "transport/packet/header/packet/header.h"
#include "transport/version/version/version.h"

/* RFC 9000 17.2: assemble a complete long header (Initial 17.2.2 with Token, or
 * Handshake 17.2.4 without), then protect. pn_len is fixed at 4 (byte0's low
 * bits are forced to agree). */
#define QUIC_TX_PN_LEN 4u

/* d->version 0 is every pre-existing positional quic_tx_desc initializer
 * (written before this field existed) -- treat it as the QUIC v1 they all
 * meant, never as the wire value 0 (RFC 8999 6.1 reserves that for Version
 * Negotiation, which this builder never emits). */
static u32 tx_version_or_v1(u32 v) { return v ? v : QUIC_VERSION_1; }

/* Assemble the long header into hdr/ho and fill io with the seal_io for the
 * result -- shared by quic_tx_packet and quic_tx_packet_suite. Returns 1 on
 * success, 0 on overflow. */
static int tx_build_hdr(
    const quic_tx_desc*   d,
    u8*                   hdr,
    usz                   hdr_cap,
    quic_mspan            out,
    quic_protect_seal_io* io) {
  usz            len_off = 0;
  quic_obuf      ho      = quic_obuf_of(hdr, hdr_cap);
  quic_lhdr_desc h       = {d->byte0,      tx_version_or_v1(d->version),
                            d->dcid,       d->scid,
                            d->is_initial, d->token,
                            d->frames.n,   d->pn,
                            QUIC_TX_PN_LEN};
  if (quic_lhdr_build(&h, &ho, &len_off) == 0) return 0;
  *io = (quic_protect_seal_io){
      quic_span_of(hdr, ho.len),
      ho.len - QUIC_TX_PN_LEN,
      QUIC_TX_PN_LEN,
      d->pn,
      d->frames,
      out};
  return 1;
}

usz quic_tx_packet(
    const quic_protect_keys* k, const quic_tx_desc* d, quic_mspan out) {
  u8                   hdr[64 + 2 * WIRED_MAX_CID_LEN];
  quic_protect_seal_io io;
  if (!tx_build_hdr(d, hdr, sizeof(hdr), out, &io)) return 0;
  return quic_protect_seal(k, &io);
}

/* Same as quic_tx_packet, but seals under the given negotiated TLS 1.3
 * cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
usz quic_tx_packet_suite(
    u16                      suite,
    const quic_protect_keys* k,
    const quic_tx_desc*      d,
    quic_mspan               out) {
  u8                   hdr[64 + 2 * WIRED_MAX_CID_LEN];
  quic_protect_seal_io io;
  if (!tx_build_hdr(d, hdr, sizeof(hdr), out, &io)) return 0;
  return quic_protect_seal_suite(suite, k, &io);
}
