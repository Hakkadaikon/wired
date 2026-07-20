#ifndef QUIC_SCHEDULE_DRIVE_KEYSCHEDULE_H
#define QUIC_SCHEDULE_DRIVE_KEYSCHEDULE_H

#include "common/bytes/span/span.h"
#include "tls/handshake/core/tls/initial.h"

/**
 * @file
 * RFC 8446 7.1: order-driven key schedule. Drives the existing secret/key
 * derivations in lock-step with handshake progress: Early -> Handshake
 * (mix in ECDHE) -> Master, each stage producing traffic keys. Out-of-order
 * advances are rejected.
 */

/**
 * which: handshake/application packet-protection keys per direction.
 */
enum {
  QUIC_KS_CLIENT_HS = 0, /**< client handshake traffic keys */
  QUIC_KS_SERVER_HS = 1, /**< server handshake traffic keys */
  QUIC_KS_CLIENT_AP = 2, /**< client application (1-RTT) traffic keys */
  QUIC_KS_SERVER_AP = 3, /**< server application (1-RTT) traffic keys */
};

/**
 * Key schedule state: the current stage, the Master Secret once reached, and
 * the four traffic key sets indexed by the QUIC_KS_* constants.
 */
typedef struct {
  int stage;                 /**< 0=init/early, 1=handshake, 2=master */
  u8  master[QUIC_HKDF_PRK]; /**< Master Secret (derived on
                                reaching stage 1) */
  quic_initial_keys keys[4]; /**< traffic keys indexed by QUIC_KS_* */
  u8 client_ap_secret[QUIC_HKDF_PRK]; /**< client_application_traffic_secret_0
                                       * (RFC 8446 7.1), retained past stage 2
                                       * so RFC 9001 6 key updates can derive
                                       * the next generation from it */
  u8 server_ap_secret[QUIC_HKDF_PRK]; /**< server_application_traffic_secret_0,
                                       * retained for the same reason on the
                                       * send side (RFC 9001 6.2) */
  u16 suite; /**< negotiated TLS 1.3 cipher suite (RFC 8446 B.4) for the
              * Handshake/1-RTT levels this schedule derives; set by
              * quic_keysched_init to AES_128_GCM_SHA256 and overridable via
              * quic_keysched_set_suite before advance_handshake. Initial
              * packet protection (RFC 9001 5.2) is unaffected -- it derives
              * separately and is always AES-128-GCM. */
} quic_keysched;

/**
 * Enter the Early Secret stage.
 *
 * @param st schedule state to initialize
 */
void quic_keysched_init(quic_keysched* st);

/**
 * Override the cipher suite advance_handshake/advance_master derive
 * Handshake/1-RTT keys for (RFC 8446 B.4). Call before advance_handshake;
 * quic_keysched_init already set the AES_128_GCM_SHA256 default, so callers
 * that never negotiate ChaCha20 need not call this at all.
 *
 * @param st    schedule state to configure
 * @param suite negotiated TLS 1.3 cipher suite code point
 */
void quic_keysched_set_suite(quic_keysched* st, u16 suite);

/**
 * ServerHello received: derive Handshake Secret from the ECDHE shared secret
 * and the client/server handshake traffic keys over the transcript.
 *
 * @param st         schedule state (must be in the init stage)
 * @param ecdhe      ECDHE shared secret
 * @param transcript raw transcript bytes (ClientHello..ServerHello), hashed
 *                   internally
 * @return 1 on success, 0 if the stage is not init (order violation).
 */
int quic_keysched_advance_handshake(
    quic_keysched* st, quic_span ecdhe, quic_span transcript);

/**
 * Same as quic_keysched_advance_handshake, but for a PSK-resumption
 * handshake (RFC 8446 7.1's key schedule diagram): Handshake Secret is
 * derived from Early Secret = HKDF-Extract(0, PSK) instead of
 * HKDF-Extract(0, 0), matching quic_tls_handshake_secret_psk. ECDHE is still
 * mixed in either way -- this SDK never runs PSK-only (no (EC)DHE).
 *
 * @param st         schedule state (must be in the init stage)
 * @param psk        the accepted ticket's resumption secret (QUIC_HKDF_PRK
 *                   bytes)
 * @param ecdhe      ECDHE shared secret
 * @param transcript raw transcript bytes (ClientHello..ServerHello), hashed
 *                   internally
 * @return 1 on success, 0 if the stage is not init (order violation).
 */
int quic_keysched_advance_handshake_psk(
    quic_keysched* st, quic_span psk, quic_span ecdhe, quic_span transcript);

/**
 * Finished processed: derive Master Secret and the application traffic keys.
 *
 * @param st             schedule state (must be in the handshake stage)
 * @param transcript     raw transcript bytes (ClientHello..server Finished),
 *                       hashed internally
 * @param transcript_len number of bytes at transcript
 * @return 1 on success, 0 if the stage is not handshake (order violation).
 */
int quic_keysched_advance_master(
    quic_keysched* st, const u8* transcript, usz transcript_len);

/**
 * If the keys for `which` have been derived, point *out at them and return 1;
 * otherwise return 0.
 *
 * *out points into st and stays valid while st lives.
 *
 * @param st    schedule state to query
 * @param which key selector (QUIC_KS_*)
 * @param out   receives a pointer to the derived keys
 * @return 1 if derived, 0 otherwise.
 */
int quic_keysched_get(
    const quic_keysched* st, int which, const quic_initial_keys** out);

/**
 * The retained client_application_traffic_secret_0, valid once stage 2 is
 * reached (same guard as quic_keysched_get with QUIC_KS_CLIENT_AP).
 *
 * @param st  schedule state to query
 * @param out receives a pointer to the QUIC_HKDF_PRK-byte secret
 * @return 1 if derived, 0 otherwise.
 */
int quic_keysched_client_ap_secret(const quic_keysched* st, const u8** out);

/**
 * The retained server_application_traffic_secret_0, valid once stage 2 is
 * reached. Same shape as quic_keysched_client_ap_secret, for the send side.
 *
 * @param st  schedule state to query
 * @param out receives a pointer to the QUIC_HKDF_PRK-byte secret
 * @return 1 if derived, 0 otherwise.
 */
int quic_keysched_server_ap_secret(const quic_keysched* st, const u8** out);

#endif
