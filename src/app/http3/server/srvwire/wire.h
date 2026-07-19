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
 * to acknowledge (< 0 for none), the TLS flight to wrap in CRYPTO, and the
 * CRYPTO stream offset of the flight's first byte (RFC 9000 19.6; 0 for an
 * unsplit flight, the chunk's start offset when a flight is split across
 * packets).
 *
 * dcid and hdr_dcid are distinct on purpose. dcid is the Initial KEY
 * DERIVATION input (RFC 9001 5.2: the client's original DCID, fixed for the
 * connection's whole handshake; unused by seal_handshake, whose keys the
 * caller supplies). hdr_dcid is the value WRITTEN INTO the packet header's
 * Destination Connection ID field (RFC 9000 7.2 / 17.2: the peer's SCID --
 * possibly zero-length, e.g. Chrome). They coincide only by accident;
 * writing dcid into the header addresses a datagram the peer does not
 * recognize as its own and silently discards (RFC 9000 5.1). */
typedef struct {
  quic_span dcid;     /**< Initial key derivation input (RFC 9001 5.2) */
  quic_span hdr_dcid; /**< header Destination Connection ID (RFC 9000 7.2) */
  quic_span scid;
  u64       pn;
  i64       ack_pn;
  quic_span tls;
  u64       crypto_off;
} quic_srvwire_seal_in;

/* RFC 9001 5.2: seal a TLS flight (e.g. ServerHello) into a server Initial
 * packet under the server Initial keys derived from in->dcid, addressed to
 * in->hdr_dcid. When in->ack_pn >= 0 the flight leads with an ACK frame
 * acknowledging that received client packet number (RFC 9000 13.2.1:
 * ack-eliciting Initials must be acknowledged so the peer stops its PTO
 * retransmissions); ack_pn < 0 emits CRYPTO only. Returns 1 with out->len
 * set, or 0 on overflow. */
int quic_srvwire_seal_initial(const quic_srvwire_seal_in* in, quic_obuf* out);

/* Seal pre-built frame bytes (in->tls holds raw frames, e.g. a
 * CONNECTION_CLOSE refusing the connection) into a padded server Initial
 * without CRYPTO wrapping, plus the usual trailing ACK when ack_pn >= 0
 * (RFC 9000 17.2.2 / 19.19). Returns 1 with out->len set, or 0 on overflow.
 */
int quic_srvwire_seal_initial_frames(
    const quic_srvwire_seal_in* in, quic_obuf* out);

/* Same as quic_srvwire_seal_initial_frames but WITHOUT the 1200-byte PADDING
 * floor. Only for packets that are not ack-eliciting (e.g. an ACK-only
 * Initial): RFC 9000 14.1's expansion rule does not apply to those, and the
 * small datagram matters -- it spends ~25x less of the RFC 9000 8.1 antiamp
 * budget than a padded one (a padded partial-ClientHello ack starved the
 * amplificationlimit flight's tail by exactly its padding). */
int quic_srvwire_seal_initial_frames_lean(
    const quic_srvwire_seal_in* in, quic_obuf* out);

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
    const quic_srvwire_open_initial_in* in, quic_mspan pkt, quic_span* tls);

/* RFC 9001 5: seal a TLS flight into a Handshake packet under caller-supplied
 * directional keys (from quic_keysched_get). When in->ack_pn >= 0 the flight
 * leads with an ACK frame for that received Handshake-space packet number
 * (RFC 9000 13.2.1); ack_pn < 0 emits CRYPTO only. Returns 1 with out->len
 * set, or 0 on overflow. */
int quic_srvwire_seal_handshake(
    const quic_protect_keys* k, const quic_srvwire_seal_in* in, quic_obuf* out);

/* Same as quic_srvwire_seal_handshake, but seals under the given negotiated
 * TLS 1.3 cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int quic_srvwire_seal_handshake_suite(
    u16                         suite,
    const quic_protect_keys*    k,
    const quic_srvwire_seal_in* in,
    quic_obuf*                  out);

/* RFC 9001 5: open a Handshake packet sealed by quic_srvwire_seal_handshake.
 * Returns 1, or 0 on authentication failure or short input. */
int quic_srvwire_open_handshake(
    const quic_protect_keys* k, quic_mspan pkt, quic_span* tls);

/* Same as quic_srvwire_open_handshake, but opens under the given negotiated
 * TLS 1.3 cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int quic_srvwire_open_handshake_suite(
    u16 suite, const quic_protect_keys* k, quic_mspan pkt, quic_span* tls);

#endif
