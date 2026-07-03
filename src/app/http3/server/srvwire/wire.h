#ifndef QUIC_SRVWIRE_WIRE_H
#define QUIC_SRVWIRE_WIRE_H

#include "common/bytes/span/span.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "tls/handshake/core/tls/initial.h"
#include "transport/packet/protect/protect/protect.h"

/* RFC 9000 17.2 / RFC 9001 5: server-direction handshake wire codec. Wraps a
 * TLS flight in CRYPTO frames and seals it into an Initial or Handshake packet,
 * and the inverse on open. This is the seal/open glue (CRYPTO-frame emit +
 * extract, server-direction Initial keys) that the packet builders do not own,
 * shared by the server wire loop and the client wire path. 1-RTT carries STREAM
 * frames, not CRYPTO, and quic_hspkt_onertt_build/open already take raw
 * payload, so no 1-RTT wrapper lives here. */

/* Remaining arguments of quic_srvwire_seal_initial/seal_handshake beyond the
 * key material and out: the connection ids, packet number, the client packet
 * to acknowledge (< 0 for none), and the TLS flight to wrap in CRYPTO. */
typedef struct {
  quic_span dcid;
  quic_span scid;
  u64       pn;
  i64       ack_pn;
  quic_span tls;
} quic_srvwire_seal_in;

/* RFC 9001 5.2: seal a TLS flight (e.g. ServerHello) into a server Initial
 * packet under the server Initial keys derived from in->dcid. When
 * in->ack_pn >= 0 the flight leads with an ACK frame acknowledging that
 * received client packet number (RFC 9000 13.2.1: ack-eliciting Initials must
 * be acknowledged so the peer stops its PTO retransmissions); ack_pn < 0
 * emits CRYPTO only. Returns 1 with out->len set, or 0 on overflow. */
int quic_srvwire_seal_initial(const quic_srvwire_seal_in *in, quic_obuf *out);

/* The client's original DCID (Initial keys are derived from it) and the
 * packet number the caller expects (currently unused, reserved). */
typedef struct {
  quic_span dcid;
  u64       pn;
} quic_srvwire_open_initial_in;

/* RFC 9001 5.2: open a server Initial sealed by quic_srvwire_seal_initial. On
 * success *tls points at the recovered flight within pkt and *tls_len holds its
 * length. Returns 1, or 0 on authentication failure or short input. */
int quic_srvwire_open_initial(
    const quic_srvwire_open_initial_in *in, quic_mspan pkt, quic_span *tls);

/* RFC 9001 5: seal a TLS flight into a Handshake packet under caller-supplied
 * directional keys (from quic_keysched_get). When in->ack_pn >= 0 the flight
 * leads with an ACK frame for that received Handshake-space packet number
 * (RFC 9000 13.2.1); ack_pn < 0 emits CRYPTO only. Returns 1 with out->len
 * set, or 0 on overflow. */
int quic_srvwire_seal_handshake(
    const quic_protect_keys *k, const quic_srvwire_seal_in *in, quic_obuf *out);

/* RFC 9001 5: open a Handshake packet sealed by quic_srvwire_seal_handshake.
 * Returns 1, or 0 on authentication failure or short input. */
int quic_srvwire_open_handshake(
    const quic_protect_keys *k, quic_mspan pkt, quic_span *tls);

#endif
