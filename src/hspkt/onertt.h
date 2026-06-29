#ifndef QUIC_HSPKT_ONERTT_H
#define QUIC_HSPKT_ONERTT_H

#include "tls/initial.h"
#include "aes/aes.h"

/* RFC 9000 17.3 / RFC 9001 5: 1-RTT (short header) packet protection. The
 * short header is byte0 (high bit 0, fixed bit set), the Destination
 * Connection ID, and a 4-byte packet number. Sealed and header-protected with
 * the 1-RTT keys. */

/* Build one protected 1-RTT packet into out (cap bytes); length to *out_len.
 * Returns 1 on success, 0 on overflow. */
int quic_hspkt_onertt_build(const quic_initial_keys *keys, const quic_aes128 *hp,
                            const u8 *dcid, u8 dcid_len, u64 pn,
                            const u8 *payload, usz payload_len,
                            u8 *out, usz cap, usz *out_len);

/* Open a 1-RTT packet built by quic_hspkt_onertt_build. largest_pn is the
 * largest packet number already received in the 1-RTT space (0 before any),
 * used to recover the full packet number from its truncated form (RFC 9000
 * A.3) so the AEAD nonce matches the sender's. On success *payload points at
 * the plaintext within pkt and *payload_len holds its length. Returns 1 on
 * success, 0 on authentication failure or short input. */
int quic_hspkt_onertt_open(const quic_initial_keys *keys, const quic_aes128 *hp,
                           u8 *pkt, usz len, u8 dcid_len, u64 largest_pn,
                           const u8 **payload, usz *payload_len);

#endif
