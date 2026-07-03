#ifndef WIRED_SRVLOOP_SEND_H
#define WIRED_SRVLOOP_SEND_H

#include "common/bytes/span/span.h"
#include "tls/handshake/roles/server/server.h"

/** @file
 * RFC 9001 5 / 5.1: seal server-direction outbound packets. The server always
 * seals with its own-direction keys: Initial keys for the ServerHello,
 * SERVER_HS for the Handshake flight, SERVER_AP for 1-RTT payloads. The DCID
 * written toward the client is the client's source id; the SCID is the
 * server's iscid. */

/** Remaining arguments of wired_srvloop_send_initial/send_handshake/send_onertt
 * beyond s and out: the connection id to write as the reply's DCID (used by
 * the Handshake and 1-RTT paths; send_initial instead uses the odcid/iscid
 * recorded at boot), the packet number, the client packet to acknowledge
 * (< 0 for none, unused by send_onertt), and the payload — a TLS flight to
 * wrap in CRYPTO for Initial/Handshake, or the raw 1-RTT payload for
 * send_onertt. */
typedef struct {
  quic_span cli_scid; /**< reply DCID for the Handshake/1-RTT sends; unused
                         by send_initial */
  u64       pn;       /**< the packet number to seal with */
  i64       ack_pn;   /**< client packet to acknowledge, < 0 for none */
  quic_span payload;  /**< TLS flight (Initial/Handshake) or raw 1-RTT bytes */
} wired_srvloop_send_in;

/** Seal a ServerHello TLS flight into a server Initial packet. When
 * in->ack_pn >= 0 the flight acknowledges that received client Initial packet
 * number (RFC 9000 13.2.1); ack_pn < 0 sends CRYPTO only.
 * @param s the server orchestrator holding the sealing keys
 * @param in the packet number, ACK target, and TLS flight (in->cli_scid is
 *   unused here; the Initial's ids come from the odcid/iscid recorded at
 *   boot)
 * @param out receives the sealed packet
 * @return 1 with out->len set, 0 on overflow. */
int wired_srvloop_send_initial(
    const wired_server *s, const wired_srvloop_send_in *in, quic_obuf *out);

/** Seal a Handshake TLS flight under SERVER_HS. When in->ack_pn >= 0 the
 * flight acknowledges that received Handshake-space packet number (RFC 9000
 * 13.2.1).
 * @param s the server orchestrator holding the sealing keys
 * @param in the reply DCID, packet number, ACK target, and TLS flight
 * @param out receives the sealed packet
 * @return 1 with out->len set, or 0 if the key is not derived or on
 *   overflow. */
int wired_srvloop_send_handshake(
    const wired_server *s, const wired_srvloop_send_in *in, quic_obuf *out);

/** Seal a raw 1-RTT payload (for example HANDSHAKE_DONE) under SERVER_AP.
 * in->ack_pn is unused (1-RTT sealing never ACKs).
 * @param s the server orchestrator holding the sealing keys
 * @param in the reply DCID, packet number, and raw 1-RTT payload
 * @param out receives the sealed packet
 * @return 1 with out->len set, or 0 if the key is not derived or on
 *   overflow. */
int wired_srvloop_send_onertt(
    const wired_server *s, const wired_srvloop_send_in *in, quic_obuf *out);

#endif
