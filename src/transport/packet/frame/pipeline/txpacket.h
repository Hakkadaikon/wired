#ifndef QUIC_PIPELINE_TXPACKET_H
#define QUIC_PIPELINE_TXPACKET_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5: assemble and protect one outbound long-header packet. The header
 * is the complete RFC 9000 17.2 form: byte0, version, DCID, SCID, an
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
  /** Long header Version field (RFC 9000 17.2). 0 (the zero-value default of
   * an existing positional initializer that predates this field) means QUIC
   * v1 -- 0 is never itself a valid version to send here (RFC 8999 6.1
   * reserves it for Version Negotiation, which this builder does not emit).
   */
  u32 version;
} quic_tx_desc;

/* Build header + protect_seal into out. Returns the protected length, or 0
 * on overflow (AES-128-GCM; equivalent to quic_tx_packet_suite with suite =
 * QUIC_TLS_AES_128_GCM_SHA256). */
usz quic_tx_packet(
    const quic_protect_keys* k, const quic_tx_desc* d, quic_mspan out);

/* Same as quic_tx_packet, but seals under the given negotiated TLS 1.3
 * cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
usz quic_tx_packet_suite(
    u16                      suite,
    const quic_protect_keys* k,
    const quic_tx_desc*      d,
    quic_mspan               out);

#endif
