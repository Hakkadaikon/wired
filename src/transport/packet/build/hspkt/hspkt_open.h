#ifndef QUIC_HSPKT_HSPKT_OPEN_H
#define QUIC_HSPKT_HSPKT_OPEN_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5: open a Handshake packet built by quic_hspkt_build. Removes
 * header protection, recovers the packet number from the header, and
 * AEAD-opens the payload in place with k. On success *payload views the
 * plaintext within pkt. Returns 1 on success, 0 on authentication failure or
 * short input (AES-128-GCM; equivalent to quic_hspkt_open_suite with suite =
 * QUIC_TLS_AES_128_GCM_SHA256). */
int quic_hspkt_open(
    const quic_protect_keys* k, quic_mspan pkt, quic_span* payload);

/* Same as quic_hspkt_open, but opens under the given negotiated TLS 1.3
 * cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int quic_hspkt_open_suite(
    u16 suite, const quic_protect_keys* k, quic_mspan pkt, quic_span* payload);

#endif
