#ifndef QUIC_SRVBOOT_SRVBOOT_H
#define QUIC_SRVBOOT_SRVBOOT_H

#include "app/http3/server/srvloop/srvloop.h"
#include "tls/handshake/roles/server/server.h"

/* RFC 9000 17.2 / RFC 9001 5 / RFC 8446 4.4: cold-start a server connection
 * from a client Initial datagram. The symmetric partner of
 * quic_srvloop_step: srvloop_step drives the live connection, this bootstraps
 * it. Both are socket-free (buffer in, sealed replies out) so the SDK core
 * stays kernel-free; the caller does the UDP send. */

/* The fixed server identity a bootstrap needs: the X25519 handshake key pair,
 * the ECDSA P-256 signing scalar the server builds its end-entity certificate
 * from, the server's source connection id (written in every reply), and the
 * ServerHello random. All views; the caller keeps them alive for the call. */
typedef struct {
  const u8 *priv;      /* X25519 private, 32 bytes */
  const u8 *pub;       /* X25519 public, 32 bytes */
  const u8 *cert_seed; /* ECDSA P-256 signing scalar, 32 bytes */
  const u8 *scid;      /* server source connection id */
  u8        scid_len;
  const u8 *random; /* ServerHello.random, 32 bytes */
} wired_srvboot_id;

/* RFC 9000 17.2: 1 if dg is a long-header Initial datagram (a Handshake or
 * short-header packet is the live connection continuing, not a new Initial). */
int wired_srvboot_is_initial(const u8 *dg, usz len);

/* Recover the ClientHello from the protected Initial datagram, initialize the
 * server and its HTTP/3 loop with `id`, build the server flight, and seal it
 * into out as a server Initial (ServerHello, acknowledging the client Initial)
 * followed by a Handshake packet (Certificate/CertificateVerify/Finished),
 * concatenated. Sets *out_len. Returns 1 on success, 0 if the datagram is not
 * a valid Initial, the open/reassembly fails, or the flight cannot be built.
 * The caller registers its request handler on l via quic_srvloop_set_handler.
 */
int wired_srvboot_accept(
    quic_server            *s,
    quic_srvloop           *l,
    const wired_srvboot_id *id,
    u8                     *dgram,
    usz                     len,
    u8                     *out,
    usz                     cap,
    usz                    *out_len);

#endif
