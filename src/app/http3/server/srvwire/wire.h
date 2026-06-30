#ifndef QUIC_SRVWIRE_WIRE_H
#define QUIC_SRVWIRE_WIRE_H

#include "tls/handshake/core/tls/initial.h"
#include "crypto/symmetric/aead/aes/aes.h"

/* RFC 9000 17.2 / RFC 9001 5: server-direction handshake wire codec. Wraps a
 * TLS flight in CRYPTO frames and seals it into an Initial or Handshake packet,
 * and the inverse on open. This is the seal/open glue (CRYPTO-frame emit +
 * extract, server-direction Initial keys) that the packet builders do not own,
 * shared by the server wire loop and the client wire path. 1-RTT carries STREAM
 * frames, not CRYPTO, and quic_hspkt_onertt_build/open already take raw payload,
 * so no 1-RTT wrapper lives here. */

/* RFC 9001 5.2: seal a TLS flight (e.g. ServerHello) into a server Initial
 * packet under the server Initial keys derived from dcid. Writes the protected
 * packet into out (cap bytes) and its length to *out_len. When ack_pn >= 0 the
 * flight leads with an ACK frame acknowledging that received client packet
 * number (RFC 9000 13.2.1: ack-eliciting Initials must be acknowledged so the
 * peer stops its PTO retransmissions); ack_pn < 0 emits CRYPTO only. Returns 1,
 * or 0 on overflow. */
int quic_srvwire_seal_initial(const u8 *dcid, u8 dcid_len,
                              const u8 *scid, u8 scid_len, u64 pn, i64 ack_pn,
                              const u8 *tls, usz tls_len,
                              u8 *out, usz cap, usz *out_len);

/* RFC 9001 5.2: open a server Initial sealed by quic_srvwire_seal_initial. On
 * success *tls points at the recovered flight within pkt and *tls_len holds its
 * length. Returns 1, or 0 on authentication failure or short input. */
int quic_srvwire_open_initial(const u8 *dcid, u8 dcid_len, u8 *pkt, usz len,
                              u64 pn, const u8 **tls, usz *tls_len);

/* RFC 9001 5: seal a TLS flight into a Handshake packet under caller-supplied
 * directional keys (from quic_keysched_get). When ack_pn >= 0 the flight leads
 * with an ACK frame for that received Handshake-space packet number (RFC 9000
 * 13.2.1); ack_pn < 0 emits CRYPTO only. Returns 1, or 0 on overflow. */
int quic_srvwire_seal_handshake(const quic_initial_keys *keys,
                                const quic_aes128 *hp,
                                const u8 *dcid, u8 dcid_len,
                                const u8 *scid, u8 scid_len, u64 pn, i64 ack_pn,
                                const u8 *tls, usz tls_len,
                                u8 *out, usz cap, usz *out_len);

/* RFC 9001 5: open a Handshake packet sealed by quic_srvwire_seal_handshake.
 * Returns 1, or 0 on authentication failure or short input. */
int quic_srvwire_open_handshake(const quic_initial_keys *keys,
                                const quic_aes128 *hp,
                                u8 *pkt, usz len, u8 dcid_len,
                                const u8 **tls, usz *tls_len);

#endif
