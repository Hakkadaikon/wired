#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"
#include "transport/packet/build/vpn/vpn_open.h"

/* RFC 9000 17.2.4 / RFC 9001 5.4: parse the complete Handshake long header
 * (no Token) for the packet-number offset and Length, then remove header
 * protection and AEAD-open the payload in place. dcid_len is recovered from the
 * header itself and so is not needed from the caller. */
int quic_hspkt_open(const quic_initial_keys *hs_keys, const quic_aes128 *hp,
                    u8 *pkt, usz len, u8 dcid_len,
                    const u8 **payload, usz *payload_len)
{
    const u8 *dcid, *scid, *token;
    u8 dcl, scl;
    usz tkl, pn_off;
    u64 length;
    (void)dcid_len;
    if (!quic_lhdr_parse(pkt, len, 0, &dcid, &dcl, &scid, &scl, &token, &tkl,
                         &length, &pn_off))
        return 0;
    return quic_vpn_open(hs_keys, hp, pkt, len, pn_off, length, payload,
                         payload_len);
}
