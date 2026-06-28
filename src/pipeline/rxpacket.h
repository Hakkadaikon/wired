#ifndef QUIC_PIPELINE_RXPACKET_H
#define QUIC_PIPELINE_RXPACKET_H

#include "protect/protect.h"

/* RFC 9001 5: unprotect one inbound Initial packet built by quic_tx_packet.
 * Computes the simplified header length from dcid_len, removes header
 * protection, and AEAD-opens the payload in place. On success *frames points
 * at the plaintext frame bytes within pkt and *frames_len holds their length.
 * Returns 1 on success, 0 if authentication fails or the packet is too short. */
int quic_rx_packet(const quic_initial_keys *keys, const quic_aes128 *hp,
                   u8 *pkt, usz pkt_len, u8 dcid_len, u64 pn,
                   const u8 **frames, usz *frames_len);

#endif
