#include "hspkt/hspkt_build.h"
#include "pipeline/txpacket.h"
#include "packet/header.h"

/* RFC 9000 17.2.4: byte0 long-header form (0x80), fixed bit (0x40), type bits
 * 5-4 = Handshake (0x2), and a 4-byte packet-number length (low bits 0x03). */
#define QUIC_HSPKT_BYTE0 0xe3

/* RFC 9000 17.2.4: emit a complete Handshake long header carrying the SCID and
 * no Token field. */
int quic_hspkt_build(const quic_initial_keys *hs_keys, const quic_aes128 *hp,
                     const u8 *dcid, u8 dcid_len,
                     const u8 *scid, u8 scid_len, u64 pn,
                     const u8 *payload, usz payload_len,
                     u8 *out, usz cap, usz *out_len)
{
    usz total;
    total = quic_tx_packet(hs_keys, hp, QUIC_HSPKT_BYTE0, dcid, dcid_len, scid,
                           scid_len, 0, (const u8 *)0, 0, pn, payload,
                           payload_len, out, cap);
    if (total == 0) return 0;
    *out_len = total;
    return 1;
}
