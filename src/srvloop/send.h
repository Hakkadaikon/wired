#ifndef QUIC_SRVLOOP_SEND_H
#define QUIC_SRVLOOP_SEND_H

#include "server/server.h"

/* RFC 9001 5 / 5.1: seal server-direction outbound packets. The server always
 * seals with its own-direction keys: Initial keys for the ServerHello, SERVER_HS
 * for the Handshake flight, SERVER_AP for 1-RTT payloads. The DCID written
 * toward the client is the client's source id; the SCID is the server's iscid. */

/* Seal a ServerHello TLS flight into a server Initial packet. When ack_pn >= 0
 * the flight acknowledges that received client Initial packet number (RFC 9000
 * 13.2.1); ack_pn < 0 sends CRYPTO only. Returns 1, 0 on overflow. */
int quic_srvloop_send_initial(const quic_server *s, const u8 *cli_scid,
                              u8 cli_scid_len, u64 pn, i64 ack_pn,
                              const u8 *tls, usz tls_len,
                              u8 *out, usz cap, usz *out_len);

/* Seal a Handshake TLS flight under SERVER_HS. When ack_pn >= 0 the flight
 * acknowledges that received Handshake-space packet number (RFC 9000 13.2.1).
 * Returns 1, or 0 if the key is not derived or on overflow. */
int quic_srvloop_send_handshake(const quic_server *s, const u8 *cli_scid,
                                u8 cli_scid_len, u64 pn, i64 ack_pn,
                                const u8 *tls, usz tls_len,
                                u8 *out, usz cap, usz *out_len);

/* Seal a raw 1-RTT payload (e.g. HANDSHAKE_DONE) under SERVER_AP. Returns 1, or
 * 0 if the key is not derived or on overflow. */
int quic_srvloop_send_onertt(const quic_server *s, const u8 *cli_scid,
                             u8 cli_scid_len, u64 pn,
                             const u8 *payload, usz payload_len,
                             u8 *out, usz cap, usz *out_len);

#endif
