#include "transport/packet/frame/pipeline/txpacket.h"
#include "transport/packet/header/lhdr/lhdr_build.h"
#include "transport/packet/header/packet/header.h"

/* RFC 9000 17.2: assemble a complete long header (Initial 17.2.2 with Token, or
 * Handshake 17.2.4 without), then protect. pn_len is fixed at 4 (byte0's low
 * bits are forced to agree). */
#define QUIC_TX_PN_LEN 4u

usz quic_tx_packet(const quic_initial_keys *keys, const quic_aes128 *hp,
                   u8 byte0, const u8 *dcid, u8 dcid_len, const u8 *scid,
                   u8 scid_len, int is_initial, const u8 *token, usz token_len,
                   u64 pn, const u8 *frames, usz frames_len, u8 *out, usz cap)
{
    u8 hdr[64 + 2 * QUIC_MAX_CID_LEN];
    usz hdr_len = 0, len_off = 0;
    usz w = quic_lhdr_build(byte0, 1, dcid, dcid_len, scid, scid_len, is_initial,
                            token, token_len, frames_len, pn, QUIC_TX_PN_LEN,
                            hdr, sizeof(hdr), &hdr_len, &len_off);
    if (w == 0) return 0;
    return quic_protect_seal(keys, hp, hdr, hdr_len, hdr_len - QUIC_TX_PN_LEN,
                             QUIC_TX_PN_LEN, pn, frames, frames_len, out, cap);
}
