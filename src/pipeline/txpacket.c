#include "pipeline/txpacket.h"
#include "packet/header.h"

/* RFC 9000 17.2 simplified long header: byte0, 4-byte version (v1), dcid_len,
 * dcid, then a 4-byte packet number. Returns the header length. */
static usz build_header(u8 *hdr, u8 byte0, const u8 *dcid, u8 dcid_len, u64 pn)
{
    usz i;
    hdr[0] = byte0;
    hdr[1] = 0; hdr[2] = 0; hdr[3] = 0; hdr[4] = 1; /* QUIC v1 */
    hdr[5] = dcid_len;
    for (i = 0; i < dcid_len; i++) hdr[6 + i] = dcid[i];
    for (i = 0; i < 4; i++) hdr[6 + dcid_len + i] = (u8)(pn >> (8 * (3 - i)));
    return 10u + dcid_len;
}

usz quic_tx_packet(const quic_initial_keys *keys, const quic_aes128 *hp,
                   u8 byte0, const u8 *dcid, u8 dcid_len, u64 pn,
                   const u8 *frames, usz frames_len, u8 *out, usz cap)
{
    u8 hdr[6 + QUIC_MAX_CID_LEN + 4];
    usz hdr_len = build_header(hdr, byte0, dcid, dcid_len, pn);
    usz pn_off = 6u + dcid_len;
    return quic_protect_seal(keys, hp, hdr, hdr_len, pn_off, 4, pn,
                             frames, frames_len, out, cap);
}
