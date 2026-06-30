#ifndef QUIC_PIPELINE_RXPACKET_H
#define QUIC_PIPELINE_RXPACKET_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5: unprotect one inbound long-header packet built by quic_tx_packet.
 * Parses the complete RFC 9000 17.2 header to locate the packet number and
 * Length, removes header protection (recovering the packet-number length), and
 * AEAD-opens the payload in place. is_initial selects whether a Token field is
 * present. On success *frames points at the plaintext frame bytes within pkt
 * and *frames_len holds their length. Returns 1 on success, 0 if
 * authentication fails or the packet is malformed. */
int quic_rx_packet(const quic_initial_keys *keys, const quic_aes128 *hp,
                   u8 *pkt, usz pkt_len, int is_initial, const u8 **frames,
                   usz *frames_len);

#endif
