#ifndef QUIC_SDRV_SDRV_H
#define QUIC_SDRV_SDRV_H

#include "common/bytes/span/span.h"
#include "crypto/kdf/hkdf/hkdf.h"
#include "tls/ext/stp/server_tp.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tls/transcript.h"

/** @file
 * RFC 8446 4 / RFC 9001 4: server-side handshake driver. Receives the client
 * ClientHello and emits the real TLS bytes of the server flight (ServerHello +
 * EncryptedExtensions + Certificate + CertificateVerify + Finished). Pure
 * orchestration over the existing build/sign/key-schedule parts. */

/** Server-side handshake driver state. */
typedef struct {
  u8 server_priv[32]; /**< RFC 7748 x25519 private */
  u8 server_pub[32];  /**< RFC 7748 x25519 public */
  u8 p256_priv[32];   /**< RFC 5480 ECDSA P-256 signing scalar; also the
                       * TBS signer for a self-built certificate */
  u8 cert_buf[512];   /**< self-signed P-256 cert DER (owned) */
  /** RFC 5280 4.2.1.6: see wired_srvboot_id.san_ipv4's doc. All-zero (the
   * zero-initialized default) means omit -- 0.0.0.0 is never a real peer, so
   * this needs no separate "is it set" flag. */
  u8        san_ipv4[4];
  quic_span certs[QUIC_TLS_CERT_CHAIN_MAX]; /**< RFC 8446 4.4.2
                                             * certificate_list, leaf first
                                             * (caller-owned views in
                                             * external-chain mode) */
  usz cert_count;               /**< 0 = nothing to send (flight build fails) */
  u8  client_pub[32];           /**< RFC 8446 4.2.8 client key_share */
  u8  client_sid[32];           /**< RFC 8446 4.1.2 legacy_session_id */
  u8  client_sid_len;           /**< 0..32 */
  u8  hs_secret[QUIC_HKDF_PRK]; /**< RFC 8446 7.1 Handshake Secret */
  u8  s_hs_traffic[QUIC_HKDF_PRK]; /**< RFC 8446 7.1 server hs traffic secret */
  int hs_ready;                    /**< hs_secret derived */
  quic_transcript tr;              /**< RFC 8446 4.4.1 Transcript-Hash */
  u8              odcid[20]; /**< RFC 9000 7.3 client first Initial DCID */
  u8              odcid_len; /**< bytes used in odcid (0..20) */
  u8              iscid[20]; /**< RFC 9000 7.3 server SCID */
  u8              iscid_len; /**< bytes used in iscid (0..20) */
  quic_stp_limits limits;    /**< advertised tunable limits (0 = defaults) */
  u64 peer_max_datagram_frame_size; /**< peer's max_datagram_frame_size
                                     * (0x20, RFC 9221 3) from the ClientHello
                                     * transport parameters; 0 = not
                                     * advertised (peer does not support
                                     * DATAGRAM) */
  u64 peer_initial_max_data;        /**< peer's initial_max_data (0x04, RFC 9000
                                     * 18.2) from the ClientHello transport
                                     * parameters -- the connection-level credit
                                     * this endpoint may send the peer, before any
                                     * MAX_DATA update; 0 = absent (send nothing,
                                     * the RFC's safe default) */
  u64 peer_initial_max_stream_data_bidi_local; /**< peer's
                                                * initial_max_stream_data_bidi_local
                                                * (0x05, RFC 9000 18.2): the TP
                                                * sender's own locally-initiated
                                                * streams' credit, i.e. what
                                                * THIS endpoint may send on a
                                                * client-initiated (HTTP/3
                                                * request) stream; 0 = absent */
} quic_sdrv;

/** Inputs to quic_sdrv_init.
 *
 * server_priv_x25519/server_pub_x25519 are the ECDHE key pair. sign_priv is
 * the ECDSA P-256 signing scalar; in self-signed mode (chain is NULL or
 * chain_count is 0) it also signs the driver's own generated certificate's
 * TBS. chain/chain_count, when non-empty, are an externally issued
 * certificate chain (leaf first, views the caller keeps alive through the
 * handshake) to send instead of a self-signed certificate; chain_count over
 * QUIC_TLS_CERT_CHAIN_MAX makes the flight unbuildable (cert_count stays 0),
 * not a truncated/overflowing copy. */
typedef struct {
  const u8*        server_priv_x25519; /**< ECDHE x25519 private (32 bytes) */
  const u8*        server_pub_x25519;  /**< ECDHE x25519 public (32 bytes) */
  const u8*        sign_priv; /**< ECDSA P-256 signing scalar (32 bytes) */
  const quic_span* chain;     /**< external chain, leaf first; NULL for
                               * self-signed mode (caller keeps the views
                               * alive through the handshake) */
  usz chain_count;            /**< entries in chain; 0 = self-signed mode */
  /** RFC 5280 4.2.1.6: see wired_srvboot_id.san_ipv4's doc. 0 to omit. */
  const u8* san_ipv4;
  /** RFC 5280 4.1.2.5.1: see wired_srvboot_id.now_secs's doc. Only used in
   * self-signed mode (ignored when an external chain is given). 0 to keep
   * the fixed 2020-2030 window (tests only). */
  u64 now_secs;
} quic_sdrv_init_in;

/** Hold the server key material. If in->chain is NULL/empty, build the
 * self-signed P-256 certificate from in->sign_priv; otherwise copy the chain
 * views (leaf first) as the certificate_list to send. Init transcript/key
 * schedule.
 * @param s driver state to initialize
 * @param in key material and optional external certificate chain */
void quic_sdrv_init(quic_sdrv* s, const quic_sdrv_init_in* in);

/** RFC 9000 7.3: record the ODCID (the DCID of the client's first Initial)
 * and the ISCID (the server's source connection id) to advertise in the
 * EncryptedExtensions transport parameters. Must be called before
 * build_server_flight.
 * @param s driver state
 * @param odcid DCID of the client's first Initial packet
 * @param iscid the server's source connection id
 * @return 1 on success, 0 if either length exceeds 20. */
int quic_sdrv_set_cids(quic_sdrv* s, quic_span odcid, quic_span iscid);

/** RFC 8446 4.4.1: fold the ClientHello into the transcript and take the
 * client's x25519 key_share.
 * @param s driver state
 * @param ch_msg the ClientHello handshake message bytes
 * @param ch_len length of ch_msg in bytes
 * @return 1 on success, 0 if the key_share is absent or malformed. */
int quic_sdrv_recv_client_hello(quic_sdrv* s, const u8* ch_msg, usz ch_len);

/** Destination for quic_sdrv_build_server_flight: sh receives the
 * ServerHello, hs the EncryptedExtensions || Certificate ||
 * CertificateVerify || Finished flight. */
typedef struct {
  quic_obuf* sh; /**< receives the ServerHello */
  quic_obuf* hs; /**< receives EncryptedExtensions || Certificate ||
                  * CertificateVerify || Finished */
} quic_sdrv_flight_out;

/** RFC 8446 4.4: build the full server flight into out->sh / out->hs.
 * Derives the handshake secret over the real ECDHE.
 * @param s driver state
 * @param server_random the 32-byte ServerHello.random
 * @param out destination buffers for the ServerHello and handshake flight
 * @return 1 on success, 0 if a buffer is too small. */
int quic_sdrv_build_server_flight(
    quic_sdrv* s, const u8* server_random, const quic_sdrv_flight_out* out);

/** Point *secret at the derived Handshake Secret (verification aid).
 * @param s driver state
 * @param secret receives a pointer to the internal Handshake Secret
 * @return 1 if build_server_flight has run, 0 otherwise. */
int quic_sdrv_handshake_secret(const quic_sdrv* s, const u8** secret);

#endif
