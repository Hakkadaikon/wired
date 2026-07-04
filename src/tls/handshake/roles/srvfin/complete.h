#ifndef QUIC_SRVFIN_COMPLETE_H
#define QUIC_SRVFIN_COMPLETE_H

#include "crypto/kdf/keys/keyset.h"
#include "tls/keys/schedule_drive/keyschedule.h"

/** @file
 * RFC 9001 4.1.2: after the client Finished verifies, the server completes
 * the handshake: derive the application (1-RTT) secrets from the transcript
 * including the client Finished, install the 1-RTT key set, and mark the
 * handshake confirmed. */

/** Server handshake-completion state. */
typedef struct {
  quic_keysched* sched;     /**< the key schedule to advance to Master */
  quic_keyset*   keys;      /**< receives the server 1-RTT keys */
  int            confirmed; /**< 1 once the handshake is confirmed */
} quic_srvfin_state;

/** Bind the key schedule and key set the completion step operates on.
 * @param s completion state to initialize
 * @param sched the key schedule to advance
 * @param keys the key set to install the 1-RTT keys into */
void quic_srvfin_state_init(
    quic_srvfin_state* s, quic_keysched* sched, quic_keyset* keys);

/** Advance the key schedule to Master over the final transcript (the
 * handshake messages through the client Finished), install the server 1-RTT
 * keys, and confirm.
 *
 * The application secrets are Derive-Secret(Master, ..., transcript), which
 * hashes the raw messages internally, so this takes the raw transcript bytes
 * and length, not a precomputed hash.
 * @param s completion state
 * @param final_transcript the raw handshake messages through the client
 * Finished
 * @param final_transcript_len length of final_transcript in bytes
 * @return 1 on success, 0 on a key schedule order violation (no keys
 * installed, not confirmed). */
int quic_srvfin_complete(
    quic_srvfin_state* s, const u8* final_transcript, usz final_transcript_len);

#endif
