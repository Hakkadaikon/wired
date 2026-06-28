#ifndef QUIC_PIPELINE_TXPACKET_H
#define QUIC_PIPELINE_TXPACKET_H

#include "protect/protect.h"

/* RFC 9001 5: assemble and protect one outbound Initial packet. The header is
 * the simplified long-header form used across the pipeline: byte0, version
 * (QUIC v1), Destination Connection ID, and a 4-byte packet number. The frame
 * bytes are sealed as the payload. */

/* Build header + protect_seal into out (cap bytes). Returns the protected
 * length, or 0 on overflow. */
usz quic_tx_packet(const quic_initial_keys *keys, const quic_aes128 *hp,
                   u8 byte0, const u8 *dcid, u8 dcid_len, u64 pn,
                   const u8 *frames, usz frames_len, u8 *out, usz cap);

#endif
