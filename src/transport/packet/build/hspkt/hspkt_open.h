#ifndef QUIC_HSPKT_HSPKT_OPEN_H
#define QUIC_HSPKT_HSPKT_OPEN_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5: open a Handshake packet built by quic_hspkt_build. Removes
 * header protection, recovers the packet number from the header, and
 * AEAD-opens the payload in place with k. On success *payload views the
 * plaintext within pkt. Returns 1 on success, 0 on authentication failure or
 * short input. */
int quic_hspkt_open(
    const quic_protect_keys* k, quic_mspan pkt, quic_span* payload);

#endif
