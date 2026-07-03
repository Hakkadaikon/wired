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
} quic_keysched;

/**
 * Enter the Early Secret stage.
 *
 * @param st schedule state to initialize
 */
void quic_keysched_init(quic_keysched *st);

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
    quic_keysched *st, quic_span ecdhe, quic_span transcript);

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
    quic_keysched *st, const u8 *transcript, usz transcript_len);

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
    const quic_keysched *st, int which, const quic_initial_keys **out);

#endif
