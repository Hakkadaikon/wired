#ifndef QUIC_PIPELINE_RXPACKET_H
#define QUIC_PIPELINE_RXPACKET_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5: unprotect one inbound long-header packet built by quic_tx_packet.
 * Parses the complete RFC 9000 17.2 header to locate the packet number and
 * Length, removes header protection (recovering the packet-number length), and
 * AEAD-opens the payload in place. is_initial selects whether a Token field is
 * present. */
typedef struct {
  quic_mspan pkt;
  int        is_initial;
} quic_rx_desc;

/* On success *frames views the plaintext frame bytes within pkt. Returns 1 on
 * success, 0 if authentication fails or the packet is malformed. */
int quic_rx_packet(
    const quic_protect_keys *k, const quic_rx_desc *d, quic_span *frames);

#endif
