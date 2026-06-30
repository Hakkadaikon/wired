#ifndef QUIC_PIPELINE_TXPACKET_H
#define QUIC_PIPELINE_TXPACKET_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5: assemble and protect one outbound long-header packet. The header
 * is the complete RFC 9000 17.2 form: byte0, version (QUIC v1), DCID, SCID, an
 * Initial-only Token, Length, and a 4-byte packet number. is_initial selects
 * whether the Token fields are present (Initial 17.2.2 vs Handshake 17.2.4).
 * The frame bytes are sealed as the payload. */

/* Build header + protect_seal into out (cap bytes). Returns the protected
 * length, or 0 on overflow. */
usz quic_tx_packet(
    const quic_initial_keys *keys,
    const quic_aes128       *hp,
    u8                       byte0,
    const u8                *dcid,
    u8                       dcid_len,
    const u8                *scid,
    u8                       scid_len,
    int                      is_initial,
    const u8                *token,
    usz                      token_len,
    u64                      pn,
    const u8                *frames,
    usz                      frames_len,
    u8                      *out,
    usz                      cap);

#endif
