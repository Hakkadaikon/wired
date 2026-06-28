#include "pipeline/rxpacket.h"

int quic_rx_packet(const quic_initial_keys *keys, const quic_aes128 *hp,
                   u8 *pkt, usz pkt_len, u8 dcid_len, u64 pn,
                   const u8 **frames, usz *frames_len)
{
    usz hdr_len = 10u + dcid_len;
    usz pn_off = 6u + dcid_len;
    usz pl;
    if (pkt_len <= hdr_len) return 0;
    pl = quic_protect_open(keys, hp, pkt, pkt_len, hdr_len, pn_off, 4, pn);
    if (pl == 0) return 0;
    *frames = pkt + hdr_len;
    *frames_len = pl;
    return 1;
}
