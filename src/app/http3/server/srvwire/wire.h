#ifndef SRVWIRE_WIRE_H
#define SRVWIRE_WIRE_H

#include "common/bytes/span/span.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "tls/handshake/core/tls/initial.h"
#include "transport/packet/protect/protect/protect.h"

/* RFC 9000 17.2 / RFC 9001 5: server-direction handshake wire codec. Wraps a
 * TLS flight in CRYPTO frames and seals it into an Initial or Handshake packet,
 * and the inverse on open. This is the seal/open glue (CRYPTO-frame emit +
 * extract, server-direction Initial keys) that the packet builders do not own,
 * shared by the server wire loop and the client wire path. 1-RTT carries STREAM
 * frames, not CRYPTO, and hspkt_onertt_build/open already take raw
 * payload, so no 1-RTT wrapper lives here. */

/** Remaining arguments of srvwire_seal_initial/seal_handshake beyond the
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
  wired_span dcid;     /**< Initial key derivation input (RFC 9001 5.2) */
  wired_span hdr_dcid; /**< header Destination Connection ID (RFC 9000 7.2) */
  wired_span scid;
  u64        pn;
  i64        ack_pn;
  wired_span tls;
  u64        crypto_off;
  /** RFC 9000 13.4.1/19.3.2: cumulative ECN counts to carry on the ACK
   * (type 0x03) -- all three zero sends a plain type-0x02 ACK. The peer
   * validates ECN capability against the FIRST acknowledgment of a packet
   * it sent ECT-marked, so the Initial-space ACK must already carry these
   * or the peer declares the path not ECN capable and stops marking. */
  u64 ect0;
  u64 ect1;
  u64 ce;
} srvwire_seal_in;

/* RFC 9001 5.2: seal a TLS flight (e.g. ServerHello) into a server Initial
 * packet under the server Initial keys derived from in->dcid, addressed to
 * in->hdr_dcid. When in->ack_pn >= 0 the flight leads with an ACK frame
 * acknowledging that received client packet number (RFC 9000 13.2.1:
 * ack-eliciting Initials must be acknowledged so the peer stops its PTO
 * retransmissions); ack_pn < 0 emits CRYPTO only. Returns 1 with out->len
 * set, or 0 on overflow. */
int srvwire_seal_initial(const srvwire_seal_in* in, wired_obuf* out);

/* Same as srvwire_seal_initial, but the Initial keys, the header's
 * Version field, and byte0's long-header type bits all follow `version`
 * (RFC 9369 3.2/3.3.1) instead of assuming QUIC v1 -- what a server accepting
 * a client that already arrived speaking v2 replies with (RFC 9368 2:
 * responding in the version the peer used, no separate switch). Unknown
 * versions fail closed (0 written). */
int srvwire_seal_initial_ver(
    u32 version, const srvwire_seal_in* in, wired_obuf* out);

/* Seal pre-built frame bytes (in->tls holds raw frames, e.g. a
 * CONNECTION_CLOSE refusing the connection) into a padded server Initial
 * without CRYPTO wrapping, plus the usual trailing ACK when ack_pn >= 0
 * (RFC 9000 17.2.2 / 19.19). Returns 1 with out->len set, or 0 on overflow.
 */
int srvwire_seal_initial_frames(const srvwire_seal_in* in, wired_obuf* out);

/* Same as srvwire_seal_initial_frames but WITHOUT the 1200-byte PADDING
 * floor. Only for packets that are not ack-eliciting (e.g. an ACK-only
 * Initial): RFC 9000 14.1's expansion rule does not apply to those, and the
 * small datagram matters -- it spends ~25x less of the RFC 9000 8.1 antiamp
 * budget than a padded one (a padded partial-ClientHello ack starved the
 * amplificationlimit flight's tail by exactly its padding). */
int srvwire_seal_initial_frames_lean(
    const srvwire_seal_in* in, wired_obuf* out);

/** The client's original DCID (Initial keys are derived from it) and the
 * packet number the caller expects (currently unused, reserved). */
typedef struct {
  wired_span dcid;
  u64        pn;
} srvwire_open_initial_in;

/* RFC 9001 5.2: open a server Initial sealed by srvwire_seal_initial. On
 * success *tls points at the recovered flight within pkt and *tls_len holds its
 * length. Returns 1, or 0 on authentication failure or short input. */
int srvwire_open_initial(
    const srvwire_open_initial_in* in, wired_mspan pkt, wired_span* tls);

/* RFC 9001 5: seal a TLS flight into a Handshake packet under caller-supplied
 * directional keys (from keysched_get). When in->ack_pn >= 0 the flight
 * leads with an ACK frame for that received Handshake-space packet number
 * (RFC 9000 13.2.1); ack_pn < 0 emits CRYPTO only. Returns 1 with out->len
 * set, or 0 on overflow. */
int srvwire_seal_handshake(
    const protect_keys* k, const srvwire_seal_in* in, wired_obuf* out);

/* Same as srvwire_seal_handshake, but seals under the given negotiated
 * TLS 1.3 cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int srvwire_seal_handshake_suite(
    u16                    suite,
    const protect_keys*    k,
    const srvwire_seal_in* in,
    wired_obuf*            out);

/* RFC 9001 5: open a Handshake packet sealed by srvwire_seal_handshake.
 * Returns 1, or 0 on authentication failure or short input. */
int srvwire_open_handshake(
    const protect_keys* k, wired_mspan pkt, wired_span* tls);

/* Same as srvwire_open_handshake, but opens under the given negotiated
 * TLS 1.3 cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int srvwire_open_handshake_suite(
    u16 suite, const protect_keys* k, wired_mspan pkt, wired_span* tls);

#endif
