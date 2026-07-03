#ifndef WIRED_SRVBOOT_SRVBOOT_H
#define WIRED_SRVBOOT_SRVBOOT_H

#include "app/http3/server/srvloop/srvloop.h"
#include "common/bytes/span/span.h"
#include "tls/handshake/roles/server/server.h"

/** @file
 * RFC 9000 17.2 / RFC 9001 5 / RFC 8446 4.4: cold-start a server connection
 * from a client Initial datagram. The symmetric partner of
 * wired_srvloop_step: srvloop_step drives the live connection, this bootstraps
 * it. Both are socket-free (buffer in, sealed replies out) so the SDK core
 * stays kernel-free; the caller does the UDP send. */

/** The fixed server identity a bootstrap needs: the X25519 handshake key pair,
 * the ECDSA P-256 signing scalar the server builds its end-entity certificate
 * from, the server's source connection id (written in every reply), and the
 * ServerHello random. chain/chain_count, when non-empty, are an externally
 * issued certificate chain (leaf first) to send instead of a self-signed
 * certificate. All views; the caller keeps them alive for the call. */
typedef struct {
  const u8        *priv;        /**< X25519 private, 32 bytes */
  const u8        *pub;         /**< X25519 public, 32 bytes */
  const u8        *cert_seed;   /**< ECDSA P-256 signing scalar, 32 bytes */
  const u8        *scid;        /**< server source connection id */
  u8               scid_len;    /**< scid length in octets, at most 20 */
  const u8        *random;      /**< ServerHello.random, 32 bytes */
  const quic_span *chain;       /**< optional: external chain, leaf first */
  usz              chain_count; /**< entries in chain; 0 = self-signed */
} wired_srvboot_id;

/** RFC 9000 17.2: 1 if dg is a long-header Initial datagram (a Handshake or
 * short-header packet is the live connection continuing, not a new Initial).
 * @param dg the datagram bytes as received from the socket
 * @param len length of dg in octets
 * @return 1 if dg is a long-header Initial datagram, 0 otherwise */
int wired_srvboot_is_initial(const u8 *dg, usz len);

/** The server orchestrator and its HTTP/3 loop, freshly cold-started by
 * wired_srvboot_accept and driven together thereafter (wired_srvloop_step
 * takes the same pair). */
typedef struct {
  wired_server  *s; /**< server-side handshake orchestrator */
  wired_srvloop *l; /**< HTTP/3 wire loop driven after the bootstrap */
} wired_srvboot_conn;

/** The fixed server identity to boot with and the client's Initial datagram to
 * recover the ClientHello from. */
typedef struct {
  const wired_srvboot_id *id;    /**< fixed server identity to boot with */
  quic_mspan              dgram; /**< the client's Initial datagram */
} wired_srvboot_in;

/** The two sealed reply datagrams of a bootstrap, kept separate because the
 * Initial alone is padded to 1200 bytes (RFC 9000 14.1) and coalescing the
 * Handshake flight behind it would exceed a 1500-byte MTU datagram. The caller
 * sends each buffer as its own UDP datagram, Initial first. */
typedef struct {
  quic_obuf *initial; /**< sealed server Initial datagram (>= 1200 bytes) */
  quic_obuf *flight;  /**< sealed Handshake packet datagram */
} wired_srvboot_out;

/** Recover the ClientHello from the protected Initial datagram, initialize the
 * server and its HTTP/3 loop with in->id, build the server flight, and seal it
 * as two datagrams: a server Initial (ServerHello, acknowledging the client
 * Initial) into out->initial and a Handshake packet
 * (Certificate/CertificateVerify/Finished) into out->flight. Sets both
 * obufs' len.
 * The caller registers its request handler on conn->l via
 * wired_srvloop_set_handler.
 * @param conn the orchestrator/loop pair to cold-start
 * @param in the fixed server identity and the client's Initial datagram
 * @param out receives the sealed server Initial and Handshake datagrams
 * @return 1 on success, 0 if the datagram is not a valid Initial, the
 *   open/reassembly fails, or the flight cannot be built. */
int wired_srvboot_accept(
    const wired_srvboot_conn *conn, const wired_srvboot_in *in,
    const wired_srvboot_out *out);

#endif
