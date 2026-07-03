#ifndef WIRED_SERVER_SERVER_H
#define WIRED_SERVER_SERVER_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/sdrv/sdrv.h"
#include "tls/handshake/roles/srvfin/complete.h"
#include "transport/conn/loop/crecv/collect.h"
#include "transport/io/socket/io/udp.h"

/** @file
 * RFC 9001 4 / 4.1.2, RFC 8446 4 / 4.4.4, RFC 9000 7: server-side handshake
 * orchestrator, the symmetric peer of quic_client. Drives the verified parts
 * (sdrv folds the ClientHello and emits the server flight; srvfin verifies the
 * client Finished and, only on success, advances to Master, installs the 1-RTT
 * key set and confirms) to handshake confirmation and HANDSHAKE_DONE.
 *
 * All policy lives in those layers; the server wires them and gates 1-RTT
 * promotion on a verified client Finished. The data path (wired_server_feed)
 * is socket-free so it can be driven by buffer injection without a socket;
 * only wired_server_pump enters the kernel via io/udp. */

/** Capacity of a server flight buffer in octets. */
#define WIRED_SERVER_FLIGHT_MAX 2048
/** Capacity of the raw handshake transcript buffer in octets. */
#define WIRED_SERVER_TRANSCRIPT_MAX 4096
/** Capacity of one received UDP datagram in octets. */
#define WIRED_SERVER_DATAGRAM_MAX 1500

/** Handshake phases of the orchestrator (wired_server.phase). */
enum {
  WIRED_SERVER_HS_INITIAL = 0, /**< awaiting the ClientHello */
  WIRED_SERVER_HS_CH_RECVD,    /**< ClientHello folded, flight not sent */
  WIRED_SERVER_HS_FLIGHT_SENT, /**< server flight sent, Handshake key ready */
  WIRED_SERVER_HS_CONFIRMED    /**< client Finished verified, 1-RTT armed */
};

/** Server-side handshake orchestrator state, initialized by
 * wired_server_init. */
typedef struct {
  i64               fd;    /**< UDP socket; <0 until a socket is opened */
  quic_sockaddr_in  peer;  /**< the client's UDP address (set by pump) */
  quic_sdrv         sdrv;  /**< server-side TLS handshake driver */
  quic_keysched     sched; /**< RFC 8446 7.1 order-driven key schedule */
  quic_keyset       keys;  /**< per-protection-level QUIC key sets */
  quic_srvfin_state fin;   /**< client-Finished verification state */
  quic_crecv        crecv; /**< CRYPTO stream reassembly buffer */
  int               phase; /**< WIRED_SERVER_HS_* */
  int               hs_done_sent; /**< HANDSHAKE_DONE emitted (at most once) */
  u8  server_priv[32]; /**< RFC 7748 x25519 private (owns the ECDHE) */
  u8  tr[WIRED_SERVER_TRANSCRIPT_MAX]; /**< raw handshake transcript bytes */
  usz tr_len;            /**< bytes through the latest folded message */
  usz tr_through_sh;     /**< transcript length through ServerHello */
  usz tr_through_flight; /**< transcript length through server Finished */
} wired_server;

/** server_priv_x25519/server_pub_x25519 are the static ECDHE pair; cert_seed
 * is the ECDSA P-256 signing scalar (big-endian). chain/chain_count, when
 * non-empty, are an externally issued certificate chain (leaf first, views
 * the caller keeps alive through the handshake) to send verbatim instead of a
 * self-signed certificate; chain NULL or chain_count 0 keeps the driver's
 * default of building its own self-signed P-256 end-entity certificate from
 * cert_seed (sdrv). */
typedef struct {
  const u8        *server_priv_x25519; /**< X25519 private, 32 bytes */
  const u8        *server_pub_x25519;  /**< X25519 public, 32 bytes */
  const u8        *cert_seed;   /**< ECDSA P-256 signing scalar, big-endian */
  const quic_span *chain;       /**< optional: external chain, leaf first */
  usz              chain_count; /**< entries in chain; 0 = self-signed */
} wired_server_init_in;

/** Initialize the orchestrator with the server key material. No socket is
 * opened.
 * @param s the orchestrator to initialize
 * @param in the server key material */
void wired_server_init(wired_server *s, const wired_server_init_in *in);

/** RFC 9000 7.3: record the DCID of the client's first Initial (the ODCID the
 * server echoes) and the server's source connection id (ISCID) so the
 * EncryptedExtensions transport parameters carry the real connection ids. Must
 * be called before build_flight.
 * @param s the orchestrator to record on
 * @param odcid the DCID of the client's first Initial
 * @param iscid the server's source connection id
 * @return 1 ok, 0 if either length exceeds 20. */
int wired_server_set_cids(wired_server *s, quic_span odcid, quic_span iscid);

/** RFC 8446 4.4.1: fold a received ClientHello (TLS handshake message bytes)
 * into the transcript. Advances INITIAL -> CH_RECVD.
 * @param s the orchestrator to advance
 * @param ch_msg the ClientHello handshake message bytes
 * @param ch_len length of ch_msg in octets
 * @return 1 on success, 0 if the message is not a usable ClientHello or out
 *   of phase. */
int wired_server_recv_initial(wired_server *s, const u8 *ch_msg, usz ch_len);

/** RFC 8446 4.4 / RFC 9001 4: build the server flight (ServerHello into
 * out->sh, EncryptedExtensions||Certificate||CertificateVerify||Finished into
 * out->hs) and derive the Handshake key. Only valid after the ClientHello was
 * received. Advances CH_RECVD -> FLIGHT_SENT.
 * @param s the orchestrator to advance
 * @param server_random the ServerHello.random, 32 bytes
 * @param out receives the ServerHello and the Handshake-level flight
 * @return 1 on success, 0 otherwise. */
int wired_server_build_flight(
    wired_server *s, const u8 *server_random, const quic_sdrv_flight_out *out);

/** RFC 8446 4.4.4 / RFC 9001 4.1.2: drive the handshake with one received
 * Handshake-packet CRYPTO payload (socket-free injection). Reassembles the
 * client Finished, verifies its verify_data, and ONLY on a match advances to
 * Master, installs the 1-RTT key set and confirms (CH_RECVD/FLIGHT_SENT ->
 * CONFIRMED). A forged Finished promotes nothing.
 * @param s the orchestrator to advance
 * @param crypto_payload one Handshake-packet CRYPTO payload
 * @param len length of crypto_payload in octets
 * @return 1 if it advanced the handshake, 0 otherwise. */
int wired_server_feed(wired_server *s, const u8 *crypto_payload, usz len);

/** RFC 9001 4.1.2 / RFC 9000 19.20: write the HANDSHAKE_DONE frame, at most
 * once and only after confirmation.
 * @param s the orchestrator to emit from
 * @param out receives the HANDSHAKE_DONE frame
 * @return 1 and sets out->len, or 0 if not confirmed, already sent, or
 *   out->cap is 0. */
int wired_server_handshake_done(wired_server *s, quic_obuf *out);

/** 1 once the client Finished verified and the handshake is confirmed.
 * @param s the orchestrator to inspect
 * @return 1 once the client Finished verified and the handshake is
 *   confirmed. */
int wired_server_is_confirmed(const wired_server *s);

/** Open a UDP socket bound to port and wait for the ClientHello.
 * @param s the orchestrator that will own the socket
 * @param port UDP port to bind
 * @return 1 on success, 0 on socket/bind failure. */
int wired_server_listen(wired_server *s, u16 port);

/** One receive iteration: pull a datagram off the socket and feed it.
 * @param s the orchestrator to pump
 * @return 1 if the handshake advanced, 0 otherwise. */
int wired_server_pump(wired_server *s);

/** Pump until confirmed or max_iterations is reached (bounded so a silent or
 * hostile peer cannot wedge the server).
 * @param s the orchestrator to pump
 * @param max_iterations upper bound on receive iterations
 * @return 1 if confirmed. */
int wired_server_run_handshake(wired_server *s, int max_iterations);

/** Close the UDP socket.
 * @param s the orchestrator whose socket to close */
void wired_server_close(wired_server *s);

#endif
