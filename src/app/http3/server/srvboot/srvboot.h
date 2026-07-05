#ifndef WIRED_SRVBOOT_SRVBOOT_H
#define WIRED_SRVBOOT_SRVBOOT_H

#include "app/http3/server/srvloop/srvloop.h"
#include "common/bytes/span/span.h"
#include "tls/handshake/roles/server/server.h"
#include "transport/conn/loop/crecv/collect.h"
#include "transport/packet/header/packet/header.h"

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
  const u8*        priv;        /**< X25519 private, 32 bytes */
  const u8*        pub;         /**< X25519 public, 32 bytes */
  const u8*        cert_seed;   /**< ECDSA P-256 signing scalar, 32 bytes */
  const u8*        scid;        /**< server source connection id */
  u8               scid_len;    /**< scid length in octets, at most 20 */
  const u8*        random;      /**< ServerHello.random, 32 bytes */
  const quic_span* chain;       /**< optional: external chain, leaf first */
  usz              chain_count; /**< entries in chain; 0 = self-signed */
  u64              max_data;    /**< advertised initial_max_data; 0 = default */
  u64 max_streams_bidi; /**< advertised initial_max_streams_bidi; 0 = default */
} wired_srvboot_id;

/** RFC 9000 17.2: 1 if dg is a long-header Initial datagram (a Handshake or
 * short-header packet is the live connection continuing, not a new Initial).
 * @param dg the datagram bytes as received from the socket
 * @param len length of dg in octets
 * @return 1 if dg is a long-header Initial datagram, 0 otherwise */
int wired_srvboot_is_initial(const u8* dg, usz len);

/** The server orchestrator and its HTTP/3 loop, freshly cold-started by
 * wired_srvboot_accept and driven together thereafter (wired_srvloop_step
 * takes the same pair). */
typedef struct {
  wired_server*  s; /**< server-side handshake orchestrator */
  wired_srvloop* l; /**< HTTP/3 wire loop driven after the bootstrap */
} wired_srvboot_conn;

/** The fixed server identity to boot with and the client's Initial datagram to
 * recover the ClientHello from. */
typedef struct {
  const wired_srvboot_id* id;    /**< fixed server identity to boot with */
  quic_mspan              dgram; /**< the client's Initial datagram */
} wired_srvboot_in;

/** Most Handshake flight datagrams a bootstrap seals: 4 chunks cover a
 * 4096-byte TLS flight split at the per-datagram CRYPTO chunk size. */
#define WIRED_SRVBOOT_FLIGHT_MAX 4

/** The sealed reply datagrams of a bootstrap. The Initial is kept separate
 * because it alone is padded to 1200 bytes (RFC 9000 14.1); a TLS flight too
 * large for one MTU datagram is split into several Handshake packets
 * (RFC 9000 19.6), concatenated in flight and sliced by dgram_len. The caller
 * sends the Initial first, then each flight slice as its own UDP datagram. */
typedef struct {
  quic_obuf* initial; /**< sealed server Initial datagram (>= 1200 bytes) */
  quic_obuf* flight;  /**< all sealed Handshake datagrams, concatenated */
  usz dgram_len[WIRED_SRVBOOT_FLIGHT_MAX]; /**< each flight datagram's length */
  usz dgram_count; /**< flight datagrams sealed (their lengths sum to
                      flight->len) */
  u64 client_pn;   /**< the client Initial's recovered packet number (the one
                      the server Initial acknowledges, RFC 9000 13.2.1) */
} wired_srvboot_out;

/** Recover the ClientHello from the protected Initial datagram, initialize the
 * server and its HTTP/3 loop with in->id, build the server flight, and seal
 * it: a server Initial (ServerHello, acknowledging the client Initial) into
 * out->initial, and the Handshake flight (Certificate/CertificateVerify/
 * Finished) into out->flight as one Handshake packet datagram per CRYPTO
 * chunk (RFC 9000 19.6), recording each datagram's length in out->dgram_len
 * and the count in out->dgram_count. Sets both obufs' len.
 * The caller registers its request handler on conn->l via
 * wired_srvloop_set_handler.
 * @param conn the orchestrator/loop pair to cold-start
 * @param in the fixed server identity and the client's Initial datagram
 * @param out receives the sealed server Initial and Handshake datagrams
 * @return 1 on success, 0 if the datagram is not a valid Initial, the
 *   open/reassembly fails, or the flight cannot be built or does not fit. */
int wired_srvboot_accept(
    const wired_srvboot_conn* conn,
    const wired_srvboot_in*   in,
    wired_srvboot_out*        out);

/** Answer a long-header datagram of an unsupported version with a Version
 * Negotiation packet offering v1, connection ids swapped (RFC 9000 5.2.2 /
 * RFC 8999 6). No response for: a datagram under 1200 bytes (amplification
 * guard, RFC 9000 6), version 0 (never answer a Version Negotiation packet
 * with another, RFC 9000 6.1), a supported version, a short header, or an
 * unparseable header.
 * @param dg the received datagram
 * @param out receives the Version Negotiation packet
 * @param cap bytes available at out
 * @return bytes written, or 0 when no response is owed. */
usz wired_srvboot_vneg(quic_span dg, u8* out, usz cap);

/** One nascent connection's ClientHello reassembly across Initial datagrams:
 * a ClientHello too big for one Initial (a post-quantum hybrid key share
 * pushes it near 1.7KB) arrives as CRYPTO chunks spread over several packets
 * (RFC 9000 19.6), and the server may not build its flight until the whole
 * message is contiguous. */
typedef struct {
  quic_crecv   cr;  /**< CRYPTO stream reassembly buffer */
  wired_header hdr; /**< the first datagram's header: its DCID is the ODCID
                       the Initial keys derive from (fixed for the whole
                       boot), its SCID the id the server replies to */
  u64 largest_pn;   /**< highest Initial packet number opened so far (the one
                       the boot flight acknowledges, RFC 9000 13.2.1) */
  int any;          /**< 1 once the first datagram bound this accumulator */
  usz opened;       /**< Initial packets successfully opened so far — 0 means
                       nothing authenticated yet and the attempt is
                       abandonable without loss */
} wired_srvboot_acc;

/** Empty the accumulator for a fresh connection attempt.
 * @param a the accumulator to reset */
void wired_srvboot_acc_reset(wired_srvboot_acc* a);

/** Absorb one Initial datagram: every coalesced Initial packet in it is
 * opened with the bound ODCID's keys and its CRYPTO chunks land at their
 * stream offsets (duplicates and any arrival order are fine). The first
 * datagram binds the accumulator; later ones must repeat its DCID.
 * @param a the accumulator
 * @param dg the received datagram (opened in place)
 * @return 1 if at least one Initial packet in the datagram authenticated
 *   and was absorbed, 0 if it was refused (not an Initial, unparseable, a
 *   foreign DCID, or nothing in it opened under the bound keys). */
int wired_srvboot_acc_feed(wired_srvboot_acc* a, quic_mspan dg);

/** @param a the accumulator
 * @return 1 once the buffered CRYPTO prefix folds a complete ClientHello. */
int wired_srvboot_acc_complete(const wired_srvboot_acc* a);

/** Cold-start the connection from a completed accumulator: initialize the
 * server and loop from the bound header, fold the reassembled ClientHello,
 * and seal the flight, acknowledging the highest Initial packet number
 * received (out fields as in wired_srvboot_accept).
 * @param conn the orchestrator/loop pair to cold-start
 * @param id the fixed server identity
 * @param a a complete accumulator (wired_srvboot_acc_complete)
 * @param out receives the sealed flight and the acknowledged packet number
 * @return 1, or 0 when the accumulator is incomplete or the boot fails. */
int wired_srvboot_accept_acc(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_srvboot_acc*        a,
    wired_srvboot_out*        out);

#endif
