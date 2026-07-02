#ifndef QUIC_HSPKT_ONERTT_H
#define QUIC_HSPKT_ONERTT_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9000 17.3 / RFC 9001 5: 1-RTT (short header) packet protection. The
 * short header is byte0 (high bit 0, fixed bit set), the Destination
 * Connection ID, and a 4-byte packet number. Sealed and header-protected with
 * the 1-RTT keys. */

/* One 1-RTT packet to build: DCID, packet number, plaintext payload. */
typedef struct {
  quic_span dcid;
  u64       pn;
  quic_span payload;
} quic_hspkt_onertt_desc;

/* Build one protected 1-RTT packet into out; length to out->len.
 * Returns 1 on success, 0 on overflow. */
int quic_hspkt_onertt_build(
    const quic_protect_keys      *k,
    const quic_hspkt_onertt_desc *d,
    quic_obuf                    *out);

/* One received 1-RTT packet to open in place. largest_pn is the largest
 * packet number already received in the 1-RTT space (0 before any), used to
 * recover the full packet number from its truncated form (RFC 9000 A.3) so
 * the AEAD nonce matches the sender's. */
typedef struct {
  quic_mspan pkt;
  u8         dcid_len;
  u64        largest_pn;
} quic_hspkt_onertt_open_desc;

/* On success *payload views the plaintext within pkt. Returns 1 on success,
 * 0 on authentication failure or short input. */
int quic_hspkt_onertt_open(
    const quic_protect_keys           *k,
    const quic_hspkt_onertt_open_desc *d,
    quic_span                         *payload);

#endif
