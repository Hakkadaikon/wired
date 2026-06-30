#ifndef QUIC_CLIENT_CLIENTWIRE_H
#define QUIC_CLIENT_CLIENTWIRE_H

#include "client/client.h"

/* RFC 9001 4 / 5: real on-wire (AEAD-protected) client send/receive path,
 * the symmetric counterpart of srvwire. The plain buffer-injection path in
 * client.c (quic_client_build_initial / quic_client_feed) is kept for the
 * socket-free handshake tests; these add the protected packet codec used by the
 * loopback example.
 *
 * Per-direction key rule (RFC 9001 5): an endpoint SEALS with its own-direction
 * key and OPENS with the peer-direction key. For the client that is:
 *   seal Handshake -> CLIENT_HS,  open Handshake -> SERVER_HS
 *   seal 1-RTT     -> CLIENT_AP,  open 1-RTT     -> SERVER_AP
 * Initial keys are derived from the DCID (shared); the client seals its Initial
 * with the client-direction Initial keys and opens the server Initial with the
 * server-direction Initial keys (quic_srvwire_open_initial). */

/* RFC 9001 5.2: seal the ClientHello into a protected client Initial packet
 * (CRYPTO frame, padded to 1200) under the Initial keys derived from dcid.
 * Returns 1, or 0 on RNG/overflow. */
int quic_client_build_initial_wire(quic_client *c,
                                   const u8 *dcid, u8 dcid_len,
                                   const u8 *scid, u8 scid_len, u64 pn,
                                   u8 *out, usz cap, usz *out_len);

/* RFC 9001 5.2: open a server Initial (ServerHello) sealed by the server's
 * Initial codec, recovering the TLS flight. Opens with the server-direction
 * Initial keys from dcid. Returns 1, or 0 on authentication failure. */
int quic_client_open_initial_wire(const u8 *dcid, u8 dcid_len,
                                  u8 *pkt, usz len, u64 pn,
                                  const u8 **tls, usz *tls_len);

/* RFC 9001 5: seal a TLS flight (e.g. the client Finished) into a Handshake
 * packet under the client's own-direction Handshake key (CLIENT_HS). Returns 1,
 * or 0 if the key is not derived or on overflow. */
int quic_client_seal_handshake_wire(quic_client *c,
                                    const u8 *dcid, u8 dcid_len,
                                    const u8 *scid, u8 scid_len, u64 pn,
                                    const u8 *tls, usz tls_len,
                                    u8 *out, usz cap, usz *out_len);

/* RFC 9001 5: open a server Handshake packet under the peer-direction key
 * (SERVER_HS), recovering its TLS flight. Returns 1, or 0 if the key is not
 * derived or on authentication failure. */
int quic_client_open_handshake_wire(quic_client *c, u8 *pkt, usz len,
                                    u8 dcid_len,
                                    const u8 **tls, usz *tls_len);

/* RFC 9001 5: seal application data (e.g. an HTTP/3 GET) into a 1-RTT packet
 * under the client's own-direction key (CLIENT_AP). Returns 1, or 0 if the key
 * is not derived or on overflow. */
int quic_client_send_appdata_wire(quic_client *c,
                                  const u8 *dcid, u8 dcid_len, u64 pn,
                                  u64 stream_id, const u8 *data, usz len,
                                  int fin, u8 *out, usz cap, usz *out_len);

/* RFC 9001 5: open a 1-RTT packet (e.g. an HTTP/3 200) under the peer-direction
 * key (SERVER_AP). The packet is dropped (returns 0) unless its DCID equals our
 * own `scid` (RFC 9000 5.1) — a reply addressed to a different connection id is
 * not ours. Returns 1, or 0 on a DCID mismatch, undrived key, or auth failure. */
int quic_client_recv_appdata_wire(quic_client *c, u8 *pkt, usz len,
                                  const u8 *scid, u8 scid_len,
                                  u64 *stream_id, u64 *offset,
                                  const u8 **data, usz *data_len, int *fin);

#endif
