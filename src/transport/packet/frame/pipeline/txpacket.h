#ifndef QUIC_PIPELINE_TXPACKET_H
#define QUIC_PIPELINE_TXPACKET_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5: assemble and protect one outbound long-header packet. The header
 * is the complete RFC 9000 17.2 form: byte0, version (QUIC v1), DCID, SCID, an
 * Initial-only Token, Length, and a 4-byte packet number. is_initial selects
 * whether the Token fields are present (Initial 17.2.2 vs Handshake 17.2.4).
 * The frame bytes are sealed as the payload. */
typedef struct {
  u8        byte0;
  quic_span dcid;
  quic_span scid;
  int       is_initial;
  quic_span token;
  u64       pn;
  quic_span frames;
} quic_tx_desc;

/* Build header + protect_seal into out. Returns the protected length, or 0
 * on overflow. */
usz quic_tx_packet(
    const quic_protect_keys *k, const quic_tx_desc *d, quic_mspan out);

#endif
