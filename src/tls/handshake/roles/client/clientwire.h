#ifndef QUIC_CLIENT_CLIENTWIRE_H
#define QUIC_CLIENT_CLIENTWIRE_H

#include "tls/handshake/roles/client/client.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/stream/data/appdata/app_recv.h"
#include "transport/stream/data/appdata/app_send.h"

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

/* dcid/scid are connection ids; pn is the packet number. */
typedef struct {
  quic_span dcid;
  quic_span scid;
  u64       pn;
} quic_clientwire_hdr_in;

/* RFC 9001 5.2: seal the ClientHello into a protected client Initial packet
 * (CRYPTO frame, padded to 1200) under the Initial keys derived from hdr->dcid.
 * Returns 1, or 0 on RNG/overflow. */
int quic_client_build_initial_wire(
    quic_client* c, const quic_clientwire_hdr_in* hdr, quic_obuf* out);

/* dcid identifies the Initial keys; pkt is opened in place (header protection
 * removal); pn is the expected packet number. */
typedef struct {
  quic_span  dcid;
  quic_mspan pkt;
  u64        pn;
} quic_clientwire_open_in;

/* RFC 9001 5.2: open a server Initial (ServerHello) sealed by the server's
 * Initial codec, recovering the TLS flight. Opens with the server-direction
 * Initial keys from in->dcid. in->pkt is mutated in place (header protection
 * removal). Returns 1, or 0 on authentication failure. */
int quic_client_open_initial_wire(
    const quic_clientwire_open_in* in, quic_span* tls);

/* hdr identifies dcid/scid/pn; tls is the flight payload to seal. */
typedef struct {
  quic_clientwire_hdr_in hdr;
  quic_span              tls;
} quic_clientwire_seal_in;

/* RFC 9001 5: seal a TLS flight (e.g. the client Finished) into a Handshake
 * packet under the client's own-direction Handshake key (CLIENT_HS). Returns 1,
 * or 0 if the key is not derived or on overflow. */
int quic_client_seal_handshake_wire(
    quic_client* c, const quic_clientwire_seal_in* in, quic_obuf* out);

/* RFC 9001 5: open a server Handshake packet under the peer-direction key
 * (SERVER_HS), recovering its TLS flight. in->pkt is opened in place;
 * in->dcid_len is our connection id length. Returns 1, or 0 if the key is not
 * derived or on authentication failure. */
int quic_client_open_handshake_wire(
    quic_client* c, const quic_appdata_pkt* in, quic_span* tls);

/* RFC 9001 5: seal application data (e.g. an HTTP/3 GET) into a 1-RTT packet
 * under the client's own-direction key (CLIENT_AP). Returns 1, or 0 if the key
 * is not derived or on overflow. */
int quic_client_send_appdata_wire(
    quic_client* c, const quic_appdata_tx* in, quic_obuf* out);

/* The received packet bytes (opened in place) and our own SCID it must route
 * to (RFC 9000 5.1). */
typedef struct {
  quic_mspan pkt;
  quic_span  scid;
} quic_clientwire_recv_in;

/* RFC 9001 5: open a 1-RTT packet (e.g. an HTTP/3 200) under the peer-direction
 * key (SERVER_AP). The packet is dropped (returns 0) unless its DCID equals
 * in->scid (RFC 9000 5.1) — a reply addressed to a different connection id is
 * not ours. Fills *out (stream_id/offset/data/fin). Returns 1, or 0 on a DCID
 * mismatch, undrived key, or auth failure. */
int quic_client_recv_appdata_wire(
    quic_client* c, const quic_clientwire_recv_in* in, quic_stream_frame* out);

#endif
