#ifndef SCHEDULE_DRIVE_KEYSCHEDULE_H
#define SCHEDULE_DRIVE_KEYSCHEDULE_H

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
  KS_CLIENT_HS = 0, /**< client handshake traffic keys */
  KS_SERVER_HS = 1, /**< server handshake traffic keys */
  KS_CLIENT_AP = 2, /**< client application (1-RTT) traffic keys */
  KS_SERVER_AP = 3, /**< server application (1-RTT) traffic keys */
};

/**
 * Key schedule state: the current stage, the Master Secret once reached, and
 * the four traffic key sets indexed by the KS_* constants.
 */
typedef struct {
  int stage;                     /**< 0=init/early, 1=handshake, 2=master */
  u8  master[HKDF_PRK];          /**< Master Secret (derived on
                                         reaching stage 1) */
  initial_keys keys[4];          /**< traffic keys indexed by KS_* */
  u8 client_ap_secret[HKDF_PRK]; /**< client_application_traffic_secret_0
                                  * (RFC 8446 7.1), retained past stage 2
                                  * so RFC 9001 6 key updates can derive
                                  * the next generation from it */
  u8 server_ap_secret[HKDF_PRK]; /**< server_application_traffic_secret_0,
                                  * retained for the same reason on the
                                  * send side (RFC 9001 6.2) */
  u8 exporter_secret[HKDF_PRK];  /**< exporter_master_secret (RFC 8446
                                  * 7.1/7.5), derived alongside the
                                  * application traffic secrets on
                                  * reaching stage 2 so
                                  * tls_exporter can compute
                                  * TLS-Exporter values (e.g.
                                  * EXPORTER-WebTransport) once the
                                  * handshake completes */
  u16 suite;   /**< negotiated TLS 1.3 cipher suite (RFC 8446 B.4) for the
                * Handshake/1-RTT levels this schedule derives; set by
                * keysched_init to AES_128_GCM_SHA256 and overridable via
                * keysched_set_suite before advance_handshake. Initial
                * packet protection (RFC 9001 5.2) is unaffected -- it derives
                * separately and is always AES-128-GCM. */
  u32 version; /**< QUIC version whose label prefix the Handshake/1-RTT
                * packet-protection expands use ("quic " for v1,
                * "quicv2 " for v2 -- RFC 9369 3.3.1); set by
                * keysched_init to VERSION_1 and overridable via
                * keysched_set_version before advance_handshake. */
} keysched;

/**
 * Enter the Early Secret stage.
 *
 * @param st schedule state to initialize
 */
void keysched_init(keysched* st);

/**
 * Override the cipher suite advance_handshake/advance_master derive
 * Handshake/1-RTT keys for (RFC 8446 B.4). Call before advance_handshake;
 * keysched_init already set the AES_128_GCM_SHA256 default, so callers
 * that never negotiate ChaCha20 need not call this at all.
 *
 * @param st    schedule state to configure
 * @param suite negotiated TLS 1.3 cipher suite code point
 */
void keysched_set_suite(keysched* st, u16 suite);

/**
 * Override the QUIC version whose label prefix advance_handshake/
 * advance_master derive Handshake/1-RTT packet-protection keys with
 * (RFC 9369 3.3.1). Call before advance_handshake; keysched_init
 * already set the VERSION_1 default, so v1-only callers need not call
 * this at all.
 *
 * @param st      schedule state to configure
 * @param version negotiated QUIC version (VERSION_1 or VERSION_2)
 */
void keysched_set_version(keysched* st, u32 version);

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
int keysched_advance_handshake(
    keysched* st, wired_span ecdhe, wired_span transcript);

/**
 * Same as keysched_advance_handshake, but for a PSK-resumption
 * handshake (RFC 8446 7.1's key schedule diagram): Handshake Secret is
 * derived from Early Secret = HKDF-Extract(0, PSK) instead of
 * HKDF-Extract(0, 0), matching tls_handshake_secret_psk. ECDHE is still
 * mixed in either way -- this SDK never runs PSK-only (no (EC)DHE).
 *
 * @param st         schedule state (must be in the init stage)
 * @param psk        the accepted ticket's resumption secret (HKDF_PRK
 *                   bytes)
 * @param ecdhe      ECDHE shared secret
 * @param transcript raw transcript bytes (ClientHello..ServerHello), hashed
 *                   internally
 * @return 1 on success, 0 if the stage is not init (order violation).
 */
int keysched_advance_handshake_psk(
    keysched* st, wired_span psk, wired_span ecdhe, wired_span transcript);

/**
 * Finished processed: derive Master Secret and the application traffic keys.
 *
 * @param st             schedule state (must be in the handshake stage)
 * @param transcript     raw transcript bytes (ClientHello..server Finished),
 *                       hashed internally
 * @param transcript_len number of bytes at transcript
 * @return 1 on success, 0 if the stage is not handshake (order violation).
 */
int keysched_advance_master(
    keysched* st, const u8* transcript, usz transcript_len);

/**
 * If the keys for `which` have been derived, point *out at them and return 1;
 * otherwise return 0.
 *
 * *out points into st and stays valid while st lives.
 *
 * @param st    schedule state to query
 * @param which key selector (KS_*)
 * @param out   receives a pointer to the derived keys
 * @return 1 if derived, 0 otherwise.
 */
int keysched_get(const keysched* st, int which, const initial_keys** out);

/**
 * The retained client_application_traffic_secret_0, valid once stage 2 is
 * reached (same guard as keysched_get with KS_CLIENT_AP).
 *
 * @param st  schedule state to query
 * @param out receives a pointer to the HKDF_PRK-byte secret
 * @return 1 if derived, 0 otherwise.
 */
int keysched_client_ap_secret(const keysched* st, const u8** out);

/**
 * The retained server_application_traffic_secret_0, valid once stage 2 is
 * reached. Same shape as keysched_client_ap_secret, for the send side.
 *
 * @param st  schedule state to query
 * @param out receives a pointer to the HKDF_PRK-byte secret
 * @return 1 if derived, 0 otherwise.
 */
int keysched_server_ap_secret(const keysched* st, const u8** out);

/**
 * The retained exporter_master_secret (RFC 8446 7.1/7.5), valid once
 * stage 2 is reached (same guard as keysched_get with
 * KS_CLIENT_AP). Feed *out into tls_exporter (exporter.h) to
 * compute a TLS-Exporter value.
 *
 * @param st  schedule state to query
 * @param out receives a pointer to the HKDF_PRK-byte secret
 * @return 1 if derived, 0 otherwise.
 */
int keysched_exporter_secret(const keysched* st, const u8** out);

#endif
