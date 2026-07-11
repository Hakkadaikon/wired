#ifndef QUIC_SESSION_SESSION_H
#define QUIC_SESSION_SESSION_H

#include "common/bytes/span/span.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "tls/handshake/core/tls/initial.h"
#include "transport/conn/lifecycle/conn/conn.h"
#include "transport/conn/lifecycle/endpoint/endpoint.h"
#include "transport/io/socket/net/memlink.h"
#include "transport/packet/frame/frame/frame.h"

/* A usable QUIC session: the orchestration layer a caller actually drives.
 * It ties together the connection phase machine, the endpoint key agreement,
 * the packet-protection pipeline, and the in-memory link, so a client and a
 * server can complete a handshake and exchange 1-RTT STREAM data entirely in
 * user space — no sockets, no kernel network stack.
 *
 * Typical use:
 *   quic_memlink link; quic_memlink_init(&link);
 *   quic_session cli, srv;
 *   quic_session_init(&cli, cpriv, dcid, &link, 0);   // client
 *   quic_session_init(&srv, spriv, dcid, &link, 1);   // server
 *   quic_session_client_hello(&cli);                  // -> Initial on link
 *   quic_session_accept(&srv);                        // reads it, derives keys
 *   quic_session_finish(&cli, &srv);                  // both agree 1-RTT keys
 *   quic_session_send_stream(&srv, 4, "hi", 2, 1);    // 1-RTT data -> link
 *   quic_stream_frame got;
 *   quic_session_recv_stream(&cli, &got);             // reads and decrypts it
 */

typedef struct {
  quic_endpoint     ep;    /* key material and ECDHE */
  quic_conn         conn;  /* phase + per-space packet numbers */
  quic_initial_keys ikeys; /* Initial-level protection (both sides share) */
  quic_aes128       ihp;   /* Initial header-protection cipher */
  quic_aes128       hshp;  /* handshake/1-RTT header-protection cipher */
  quic_memlink*     link;  /* the in-memory transport */
  u8                dcid[8];
  u8                peer_pub[32]; /* the peer's X25519 share, once seen */
  int               is_server;
  int               have_peer; /* peer share recovered */
  /** Scratch for quic_session_recv_stream's unprotect: per-instance so two
   * sessions stepping concurrently never share one buffer. Backs
   * quic_session_recv_stream's out->data view, valid until this session's
   * next recv_stream call, same lifetime rule as before this became a
   * member. */
  u8 rxbuf[1200];
} quic_session;

/* Everything quic_session_init needs besides the session. */
typedef struct {
  const u8*     priv; /* [32] */
  const u8*     dcid; /* [8] */
  quic_memlink* link;
  int           is_server;
} quic_session_init_in;

/* Initialize a session over `in->link` with our private scalar and the shared
 * DCID (both ends use the same DCID to derive matching Initial keys). */
void quic_session_init(quic_session* s, const quic_session_init_in* in);

/* Client: build and send an Initial carrying a ClientHello (our X25519 share)
 * onto the link. Returns 1 on success. */
int quic_session_client_hello(quic_session* s);

/* Server: receive the client Initial from the link, unprotect it, and recover
 * the client's X25519 share into s->peer_pub. Returns 1 on success. */
int quic_session_accept(quic_session* s);

/* Complete key agreement on both ends: each derives the handshake (1-RTT)
 * keys from the ECDHE shared secret over `transcript`. The client learns the
 * server's share from `peer` (in this in-memory setup the server's public key
 * is known directly). Returns 1 on success. */
int quic_session_finish(
    quic_session* client, quic_session* server, quic_span transcript);

/* One outgoing STREAM message: the stream, its payload, and the FIN bit. */
typedef struct {
  u64       stream_id;
  quic_span data;
  int       fin;
} quic_session_msg;

/* Send a 1-RTT STREAM frame (protected with the agreed keys) onto the link.
 * Returns 1 on success, 0 before the handshake keys are ready. */
int quic_session_send_stream(quic_session* s, const quic_session_msg* m);

/* Receive and decrypt a 1-RTT STREAM frame from the link into *out (its data
 * pointer references an internal buffer valid until the next recv). Returns 1
 * on success, 0 if nothing valid was available. */
int quic_session_recv_stream(quic_session* s, quic_stream_frame* out);

#endif
