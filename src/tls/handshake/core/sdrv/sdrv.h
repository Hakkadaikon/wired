#ifndef SDRV_SDRV_H
#define SDRV_SDRV_H

#include "common/bytes/span/span.h"
#include "crypto/kdf/hkdf/hkdf.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/ext/salpn/sni_check.h"
#include "tls/ext/stp/server_tp.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tls/initial.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/keys/ticket/ticket.h"

/** @file
 * RFC 8446 4 / RFC 9001 4: server-side handshake driver. Receives the client
 * ClientHello and emits the real TLS bytes of the server flight (ServerHello +
 * EncryptedExtensions + Certificate + CertificateVerify + Finished). Pure
 * orchestration over the existing build/sign/key-schedule parts. */

/** Server-side handshake driver state. */
typedef struct {
  u8 server_priv[32]; /**< ECDHE private scalar (RFC 7748 x25519 or the
                       * P-256 SEC1 scalar, per group below); always 32
                       * bytes for either supported group. */
  u8 server_pub[65];  /**< ECDHE public key_share: 32-byte RFC 7748 x25519,
                       * or 65-byte SEC1 uncompressed P-256 (RFC 8446
                       * 4.2.8.2), per group below. */
  /** RFC 8446 4.2.7 NamedGroup negotiated for the ECDHE key_share
   * (GROUP_X25519 or GROUP_SECP256R1); GROUP_X25519 unless
   * sdrv_set_group selects otherwise. Governs how server_priv/
   * server_pub/client_pub are interpreted. */
  u16 group;
  u8  p256_priv[32]; /**< RFC 5480 ECDSA P-256 signing scalar; also the
                      * TBS signer for a self-built certificate */
  u8 cert_buf[512];  /**< self-signed P-256 cert DER (owned) */
  /** RFC 5280 4.2.1.6: see wired_srvboot_id.san_ipv4's doc. All-zero (the
   * zero-initialized default) means omit -- 0.0.0.0 is never a real peer, so
   * this needs no separate "is it set" flag. */
  u8         san_ipv4[4];
  wired_span certs[TLS_CERT_CHAIN_MAX]; /**< RFC 8446 4.4.2
                                         * certificate_list, leaf first
                                         * (caller-owned views in
                                         * external-chain mode) */
  usz cert_count;     /**< 0 = nothing to send (flight build fails) */
  u8  client_pub[65]; /**< RFC 8446 4.2.8 client key_share, group above */
  u8  client_sid[32]; /**< RFC 8446 4.1.2 legacy_session_id */
  u8  client_sid_len; /**< 0..32 */
  /** RFC 8446 4.6.1: this server's session-ticket encryption key, or
   * has_ticket_key 0 to disable resumption entirely (pre_shared_key is then
   * never inspected). Set once at sdrv_init from
   * sdrv_init_in.ticket_key. */
  u8 ticket_key[TICKET_KEY_LEN];
  /** 1 when ticket_key above is set; 0 disables resumption. */
  int has_ticket_key;
  /** RFC 8446 4.2.11/4.2.11.2: set by sdrv_recv_client_hello when the
   * ClientHello's pre_shared_key ticket opened under ticket_key and its
   * binder verified. psk_secret (the opened ticket's resumption secret) is
   * only meaningful when this is 1. */
  int psk_accepted;
  /** The opened ticket's resumption secret; meaningful when psk_accepted. */
  u8 psk_secret[TICKET_SECRET_LEN];
  /** RFC 8446 4.2.10 / RFC 9001 4.6.1/9.2: set by
   * sdrv_recv_client_hello when the ClientHello carries early_data
   * (0x002a) alongside an accepted pre_shared_key AND the presented ticket
   * is on its first use (RFC 8446 8.1 single-use enforcement,
   * zerortt_seen_check). A replayed ticket's early_data is refused
   * (this stays 0) even though psk_accepted may still be 1 -- 0-RTT alone is
   * rejected, ordinary PSK/1-RTT resumption still proceeds. */
  int early_data_accepted;
  /** RFC 8446 4.2.10 / RFC 9001 4.6.1: the 0-RTT packet-protection keys,
   * meaningful only when early_data_accepted is 1. */
  initial_keys early_keys;
  u8           hs_secret[HKDF_PRK]; /**< RFC 8446 7.1 Handshake Secret */
  u8 s_hs_traffic[HKDF_PRK]; /**< RFC 8446 7.1 server hs traffic secret */
  /** RFC 8446 7.1: the ECDHE shared secret the flight derivation computed
   * (x25519 output, or the P-256 x-coordinate -- 32 bytes either way), kept
   * so the connection's packet-protection key schedule reuses it instead of
   * repeating the scalar multiply. Meaningful once hs_ready is 1. */
  u8         ecdhe_secret[32];
  int        hs_ready; /**< hs_secret derived */
  transcript tr;       /**< RFC 8446 4.4.1 Transcript-Hash */
  /** RFC 9001 5.2 Initial-key derivation input: the DCID of the Initial
   * packet actually being processed right now. After a Retry this is the
   * Retry's own SCID (the client's second Initial is keyed off it), never
   * the original DCID -- mixing the two here breaks decryption of every
   * post-Retry Initial. */
  u8 odcid[20];
  u8 odcid_len; /**< bytes used in odcid (0..20) */
  u8 iscid[20]; /**< RFC 9000 7.3 server SCID */
  u8 iscid_len; /**< bytes used in iscid (0..20) */
  /** RFC 9000 7.3 original_destination_connection_id transport parameter
   * value: the true first Initial's DCID. Equal to odcid on the direct
   * accept path; after a Retry it is the token-recovered original while
   * odcid above has already moved on to the Retry's SCID. */
  u8 tp_odcid[20];
  u8 tp_odcid_len;      /**< bytes used in tp_odcid (0..20) */
  u8 rscid[20];         /**< RFC 9000 7.3 retry_source_connection_id --
                         * the Retry packet's SCID, advertised only when
                         * a Retry preceded this handshake */
  u8         rscid_len; /**< bytes used in rscid; 0 = no Retry */
  stp_limits limits;    /**< advertised tunable limits (0 = defaults) */
  /** stateless_reset_token (RFC 9000 10.3.1/18.2) for iscid, advertised in
   * the EncryptedExtensions transport parameters when sreset_token_set is 1.
   * The caller derives it from a restart-stable secret (sreset_key_
   * derive) -- a per-boot token would be useless, since the reset it
   * authorizes is exactly the "server lost its state" signal. */
  u8  sreset_token[16];
  u8  sreset_token_set; /**< 1 once sreset_token holds a real token */
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
  /** peer's initial_max_stream_data_bidi_remote (0x06, RFC 9000 18.2): the
   * per-stream credit for bidi streams the REMOTE endpoint (this server)
   * initiates toward the TP sender, e.g. a server-opened WebTransport bidi
   * stream; 0 = absent (send nothing until MAX_STREAM_DATA). */
  u64 peer_initial_max_stream_data_bidi_remote;
  /** peer's initial_max_stream_data_uni (0x07, RFC 9000 18.2): the
   * per-stream credit for uni streams this server opens toward the TP
   * sender, e.g. a server-opened WebTransport uni stream; 0 = absent. */
  u64 peer_initial_max_stream_data_uni;
  /** peer's initial_max_streams_uni (0x09, RFC 9000 18.2): how many uni
   * streams THIS endpoint may open toward the peer before a MAX_STREAMS
   * raise; 0 = absent (the RFC's default: open none until the peer grants).
   */
  u64          peer_initial_max_streams_uni;
  salpn_choice alpn; /**< RFC 7301 3.1/3.2: this server's negotiated
                      * ALPN protocol (h3 preferred, hq-interop
                      * fallback), from the ClientHello's ALPN
                      * extension. SALPN_NONE if the client
                      * offered neither -- the caller (server.c) must
                      * fail the handshake rather than proceed. */
  u16 cipher_suite;  /**< RFC 8446 B.4 / RFC 9001 9.3: this server's
                      * negotiated TLS 1.3 cipher suite (AES_128_GCM_
                      * SHA256 preferred, CHACHA20_POLY1305_SHA256
                      * fallback), set by sdrv_recv_client_hello.
                      * Governs ServerHello.cipher_suite and the
                      * Handshake/1-RTT key derivation and packet
                      * protection; Initial packet protection (RFC 9001
                      * 5.2) is unaffected and stays AES-128-GCM. */
  /** RFC 9001 8.2: the CRYPTO_ERROR (0x0100 | TLS alert) recorded when
   * sdrv_recv_client_hello rejects the ClientHello -- currently only
   * set to missing_extension (RFC 8446 B.2: alert 109 = 0x6d, so 0x016d)
   * when the quic_transport_parameters extension (0x39) is absent. 0 when
   * the last call succeeded. */
  u64 last_error;
  /** RFC 8446 4.1.4: set by sdrv_recv_client_hello when the
   * ClientHello carried no x25519 key_share, meaning a HelloRetryRequest
   * must be sent (sdrv_build_hrr) instead of the normal server flight.
   * Cleared once sdrv_build_hrr has produced the HRR. */
  int hrr_needed;
  /** 1 once sdrv_build_hrr has emitted a HelloRetryRequest for this
   * connection; the next sdrv_recv_client_hello call is then the
   * post-HRR second ClientHello and must offer the same cipher_suite (RFC
   * 8446 4.1.2) and gets its transcript message_hash-transformed (4.4.1). */
  int hrr_sent;
  /** The cipher_suite negotiated from ClientHello1, recorded when hrr_sent
   * becomes 1 so ClientHello2 can be checked against it. */
  u16 hrr_cipher_suite;
  /** RFC 8446 4.4.1: SHA-256(ClientHello1), computed when hrr_needed is set
   * so sdrv_build_hrr can fold the message_hash synthetic message into
   * the transcript without keeping ClientHello1's raw bytes around. */
  u8 ch1_hash[32];
  /** RFC 6066 3: the ClientHello's server_name extension checked against
   * this driver's own certificate (salpn_sni_check), set by
   * sdrv_recv_client_hello. SALPN_SNI_ABSENT when the client sent
   * no server_name (or it was malformed); this SDK's policy is to continue
   * the handshake in every case (RFC 6066 3 leaves both a mismatch alert and
   * silently continuing as valid server behavior) -- the field is exposed so
   * a caller (server.c) MAY choose to send unrecognized_name
   * (TLS_ALERT_UNRECOGNIZED_NAME) on SALPN_SNI_MISMATCH instead. */
  salpn_sni_outcome sni_outcome;
  /** RFC 9368 2.2: the QUIC version the client's Initial actually arrived
   * in, recorded via sdrv_set_client_version before
   * sdrv_recv_client_hello. 0 (never set) is treated as VERSION_1
   * everywhere it is read. */
  u32 client_version;
  /** RFC 9368 2.3: the compatible version this server selected from the
   * ClientHello's version_information transport parameter (most preferred
   * mutually supported entry), set by sdrv_recv_client_hello. 0 while no
   * version_information arrived or nothing better was offered -- the
   * flight then stays in client_version (see sdrv_wire_version). */
  u32 negotiated_version;
  /** RFC 9000 9.6/18.2: the preferred_address transport parameter this
   * flight advertises, set via sdrv_set_preferred_address before the
   * flight is built. pref_cid_len 0 (never set) omits the parameter. The
   * embedded CID carries sequence number 1 (RFC 9000 5.1.1), so whoever
   * routes it must register it, and no NEW_CONNECTION_ID frame may reuse
   * that sequence for a different CID. */
  u8 pref_v4[4];
  /** Port of the advertised IPv4 address, host byte order (encoded
   * big-endian on the wire). */
  u16 pref_v4_port;
  /** IPv6 address of the preferred_address parameter, network byte
   * order. All-zero when only IPv4 is advertised. */
  u8 pref_v6[16];
  /** Port of the advertised IPv6 address, host byte order (encoded
   * big-endian on the wire). */
  u16 pref_v6_port;
  /** The connection ID embedded in the parameter (sequence number 1). */
  u8 pref_cid[20];
  /** Length of pref_cid in bytes; 0 omits the whole parameter. */
  u8 pref_cid_len;
  /** Stateless reset token paired with the embedded CID. */
  u8 pref_token[16];
} sdrv;

/** Inputs to sdrv_set_preferred_address: both addresses in network byte
 * order, the CID the migrating client will use (sequence 1), and its
 * stateless reset token (RFC 9000 9.6/18.2). */
typedef struct {
  const u8* v4;      /**< 4 bytes */
  u16       v4_port; /**< host byte order; encoded big-endian */
  const u8* v6;      /**< 16 bytes */
  u16       v6_port; /**< host byte order; encoded big-endian */
  const u8* cid;     /**< cid_len bytes */
  u8        cid_len; /**< 1..20 */
  const u8* token;   /**< 16 bytes */
} sdrv_pref_addr;

/** RFC 9000 9.6: arm the preferred_address transport parameter for this
 * connection's flight. Call after sdrv_init, before the flight is built.
 * @param s driver state
 * @param p the addresses, CID and token to advertise. */
void sdrv_set_preferred_address(sdrv* s, const sdrv_pref_addr* p);

/** Inputs to sdrv_init.
 *
 * server_priv_x25519/server_pub_x25519 are the ECDHE key pair. sign_priv is
 * the ECDSA P-256 signing scalar; in self-signed mode (chain is NULL or
 * chain_count is 0) it also signs the driver's own generated certificate's
 * TBS. chain/chain_count, when non-empty, are an externally issued
 * certificate chain (leaf first, views the caller keeps alive through the
 * handshake) to send instead of a self-signed certificate; chain_count over
 * TLS_CERT_CHAIN_MAX makes the flight unbuildable (cert_count stays 0),
 * not a truncated/overflowing copy. */
typedef struct {
  const u8*         server_priv_x25519; /**< ECDHE x25519 private (32 bytes) */
  const u8*         server_pub_x25519;  /**< ECDHE x25519 public (32 bytes) */
  const u8*         sign_priv; /**< ECDSA P-256 signing scalar (32 bytes) */
  const wired_span* chain;     /**< external chain, leaf first; NULL for
                                * self-signed mode (caller keeps the views
                                * alive through the handshake) */
  usz chain_count;             /**< entries in chain; 0 = self-signed mode */
  /** RFC 5280 4.2.1.6: see wired_srvboot_id.san_ipv4's doc. 0 to omit. */
  const u8* san_ipv4;
  /** RFC 5280 4.1.2.5.1: see wired_srvboot_id.now_secs's doc. Only used in
   * self-signed mode (ignored when an external chain is given). 0 to keep
   * the fixed 2020-2030 window (tests only). */
  u64 now_secs;
  /** RFC 8446 4.6.1: this server's session-ticket encryption key
   * (TICKET_KEY_LEN bytes), or 0 to disable session resumption --
   * sdrv_recv_client_hello then never inspects pre_shared_key. */
  const u8* ticket_key;
} sdrv_init_in;

/** Hold the server key material. If in->chain is NULL/empty, build the
 * self-signed P-256 certificate from in->sign_priv; otherwise copy the chain
 * views (leaf first) as the certificate_list to send. Init transcript/key
 * schedule.
 * @param s driver state to initialize
 * @param in key material and optional external certificate chain */
void sdrv_init(sdrv* s, const sdrv_init_in* in);

/** RFC 9000 7.3: record the ODCID (the DCID of the client's first Initial)
 * and the ISCID (the server's source connection id) to advertise in the
 * EncryptedExtensions transport parameters. Must be called before
 * build_server_flight.
 * @param s driver state
 * @param odcid DCID of the client's first Initial packet
 * @param iscid the server's source connection id
 * @return 1 on success, 0 if either length exceeds 20. */
int sdrv_set_cids(sdrv* s, wired_span odcid, wired_span iscid);

/** RFC 8446 4.2.7: select the NamedGroup for the ECDHE key_share
 * (GROUP_X25519 or GROUP_SECP256R1). sdrv_init defaults to
 * GROUP_X25519; call this right after init, before receiving any
 * ClientHello, to use secp256r1 instead. server_priv/server_pub must already
 * hold the matching key pair (32-byte P-256 scalar + 65-byte SEC1
 * uncompressed public, in place of the x25519 pair sdrv_init took).
 * @param s driver state
 * @param group the NamedGroup to require/advertise. */
void sdrv_set_group(sdrv* s, u16 group);

/** RFC 9000 7.3, post-Retry accept: odcid is the Initial-key derivation
 * input (the Retry's own SCID -- the client's second Initial is keyed off
 * it, RFC 9001 5.2), iscid the server's own source connection id as usual,
 * and true_odcid the ORIGINAL first Initial's DCID recovered from the
 * Retry token -- advertised as original_destination_connection_id instead
 * of odcid, which has already moved on.
 * @return 1 on success, 0 if any length exceeds 20. */
int sdrv_set_cids_retried(
    sdrv* s, wired_span odcid, wired_span iscid, wired_span true_odcid);

/** Record the Retry packet's SCID for the retry_source_connection_id
 * transport parameter (RFC 9000 7.3) -- only after a Retry actually
 * happened; never call it on the direct-accept path.
 * @param s the server driver
 * @param rscid the Retry's source connection id (at most 20 bytes)
 * @return 1 on success, 0 when rscid exceeds 20 bytes */
int sdrv_set_retry_scid(sdrv* s, wired_span rscid);

/** RFC 8446 4.4.1: fold the ClientHello into the transcript and take the
 * client's x25519 key_share.
 *
 * RFC 8446 4.2.11/4.2.11.2 session resumption, only when has_ticket_key: if
 * the ClientHello carries no pre_shared_key extension, behavior is exactly
 * the full-handshake path above (psk_accepted stays 0). If it does, this
 * opens the offered ticket (its identity bytes) under ticket_key; a ticket
 * that fails to open (wrong key, malformed, tampered) is a silent MAY-
 * degrade to a full handshake (psk_accepted stays 0, no error). A ticket
 * that opens has its PSK binder verified against the resumption secret and
 * the truncated ClientHello; a binder mismatch instead makes this whole call
 * fail (0) -- RFC 8446 4.2.11.2 MUST abort the handshake, never fall back
 * silently. On a verified binder, psk_accepted is set to 1 and psk_secret
 * holds the opened ticket's resumption secret, for
 * sdrv_build_server_flight's key schedule.
 *
 * RFC 9001 8.2: a ClientHello missing the quic_transport_parameters
 * extension (0x39) is rejected before any other field is taken; s->last_error
 * is set to the missing_extension CRYPTO_ERROR (0x016d) in that case.
 * @param s driver state
 * @param ch_msg the ClientHello handshake message bytes
 * @param ch_len length of ch_msg in bytes
 * @return 1 on success (with or without an accepted PSK), 0 if the
 *   ClientHello itself is malformed/unsupported, lacks the
 *   quic_transport_parameters extension, or a presented PSK binder fails
 *   verification. */
int sdrv_recv_client_hello(sdrv* s, const u8* ch_msg, usz ch_len);

/** RFC 6066 3: the outcome of checking the last ClientHello's server_name
 * against this driver's own certificate (set by sdrv_recv_client_hello
 * via salpn_sni_check). SALPN_SNI_ABSENT if the client sent no
 * server_name (or it was malformed) or no certificate was available yet to
 * check against. A SALPN_SNI_MISMATCH never fails the handshake on its
 * own (RFC 6066 3 permits continuing); a caller that wants to enforce
 * unrecognized_name checks this and closes with
 * err_crypto(TLS_ALERT_UNRECOGNIZED_NAME) itself.
 * @param s driver state
 * @return the last checked SNI outcome. */
salpn_sni_outcome sdrv_sni_outcome(const sdrv* s);

/** RFC 6066 3: opt-in enforcement of the last checked SNI outcome. A
 * SALPN_SNI_MISMATCH sets s->last_error to
 * err_crypto(TLS_ALERT_UNRECOGNIZED_NAME) and fails; MATCH and
 * ABSENT are no-ops. Call right after a successful
 * sdrv_recv_client_hello when the caller wants unrecognized_name
 * enforced instead of RFC 6066 3's silent-continue default.
 * @param s driver state
 * @return 1 to continue, 0 if the caller must reject the handshake. */
int sdrv_enforce_sni(sdrv* s);

/** RFC 9368 2.2: record the QUIC version the client's Initial arrived in,
 * so sdrv_recv_client_hello can validate the version_information
 * parameter's Chosen Version against it (RFC 9368 4) and
 * sdrv_wire_version can fall back to it while nothing better was
 * negotiated. Call after sdrv_init, before sdrv_recv_client_hello.
 * @param s driver state
 * @param version the client Initial's long-header Version field. */
void sdrv_set_client_version(sdrv* s, u32 version);

/** RFC 9368 2.3: the QUIC version every packet of this server's flight (and
 * everything after it) must be sent and read in -- the negotiated
 * compatible version once sdrv_recv_client_hello selected one from the
 * client's version_information, else the client's own Initial version
 * (VERSION_1 when that was never recorded either).
 * @param s driver state
 * @return the connection's wire version (never 0). */
u32 sdrv_wire_version(const sdrv* s);

/** RFC 8446 4.1.4: 1 when the last sdrv_recv_client_hello call found no
 * x25519 key_share and a HelloRetryRequest must be sent before anything
 * else -- the caller must call sdrv_build_hrr instead of proceeding to
 * sdrv_build_server_flight.
 * @param s driver state
 * @return 1 if a HelloRetryRequest is pending, 0 otherwise. */
int sdrv_hrr_pending(const sdrv* s);

/** RFC 8446 4.1.4 / 4.4.1: build the HelloRetryRequest (requesting x25519,
 * this driver's only supported group) into out, fold it into the
 * transcript, and arm ClientHello2 handling: sdrv_recv_client_hello.
 * Must only be called when sdrv_hrr_pending is 1 (right after the
 * ClientHello1 that triggered it, before anything else touches the
 * transcript).
 * @param s driver state
 * @param out receives the HelloRetryRequest message bytes
 * @return 1 on success, 0 if out is too small. */
int sdrv_build_hrr(sdrv* s, wired_obuf* out);

/** RFC 9001 8.2 / RFC 9000 20.1: the CRYPTO_ERROR recorded by the last
 * sdrv_recv_client_hello call, or 0 if it succeeded.
 * @param s driver state
 * @return the CRYPTO_ERROR code (0x0100 | TLS alert), or 0. */
u64 sdrv_last_error(const sdrv* s);

/** Destination for sdrv_build_server_flight: sh receives the
 * ServerHello, hs the EncryptedExtensions || Certificate ||
 * CertificateVerify || Finished flight. */
typedef struct {
  wired_obuf* sh; /**< receives the ServerHello */
  wired_obuf* hs; /**< receives EncryptedExtensions || Certificate ||
                   * CertificateVerify || Finished */
} sdrv_flight_out;

/** RFC 8446 4.4: build the full server flight into out->sh / out->hs.
 * Derives the handshake secret over the real ECDHE.
 * @param s driver state
 * @param server_random the 32-byte ServerHello.random
 * @param out destination buffers for the ServerHello and handshake flight
 * @return 1 on success, 0 if a buffer is too small. */
int sdrv_build_server_flight(
    sdrv* s, const u8* server_random, const sdrv_flight_out* out);

/** Point *secret at the derived Handshake Secret (verification aid).
 * @param s driver state
 * @param secret receives a pointer to the internal Handshake Secret
 * @return 1 if build_server_flight has run, 0 otherwise. */
int sdrv_handshake_secret(const sdrv* s, const u8** secret);

/** RFC 8446 4.2.10 / RFC 9001 4.6.1: the 0-RTT packet-protection keys
 * (client_early_traffic_secret's key/iv/hp), derived by
 * sdrv_recv_client_hello over the accepted PSK and the raw ClientHello
 * bytes when early_data_accepted is 1.
 * @param s driver state (sdrv_recv_client_hello must have run)
 * @param out receives the 0-RTT key/iv/hp
 * @return 1 if early_data_accepted, 0 otherwise (out untouched). */
int sdrv_early_keys(const sdrv* s, initial_keys* out);

#endif
