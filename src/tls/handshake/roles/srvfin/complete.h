#ifndef SRVFIN_COMPLETE_H
#define SRVFIN_COMPLETE_H

#include "crypto/kdf/keys/keyset.h"
#include "tls/keys/schedule_drive/keyschedule.h"

/** @file
 * RFC 9001 4.1.2: after the client Finished verifies, the server completes
 * the handshake: derive the application (1-RTT) secrets from the transcript
 * including the client Finished, install the 1-RTT key set, and mark the
 * handshake confirmed. */

/** Server handshake-completion state. */
typedef struct {
  keysched* sched;     /**< the key schedule to advance to Master */
  keyset*   keys;      /**< receives the server 1-RTT keys */
  int       confirmed; /**< 1 once the handshake is confirmed */
} srvfin_state;

/** Bind the key schedule and key set the completion step operates on.
 * @param s completion state to initialize
 * @param sched the key schedule to advance
 * @param keys the key set to install the 1-RTT keys into */
void srvfin_state_init(srvfin_state* s, keysched* sched, keyset* keys);

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
int srvfin_complete(
    srvfin_state* s, const u8* final_transcript, usz final_transcript_len);

/** Derive and install the server's 1-RTT send keys early, before the client
 * Finished arrives (0.5-RTT, RFC 9001 4.9 / RFC 8446 7.1): the application
 * traffic secrets depend only on the transcript through the SERVER
 * Finished, which is complete the moment the flight is built. Does NOT
 * confirm the handshake; a later srvfin_complete over the same transcript
 * derives identical secrets, so calling both is safe in either order.
 * @param s completion state
 * @param transcript the raw handshake messages through the server Finished
 * @param transcript_len length of transcript in bytes
 * @return 1 with the 1-RTT keys installed, 0 on a key schedule order
 * violation (nothing installed). */
int srvfin_early_send_keys(
    srvfin_state* s, const u8* transcript, usz transcript_len);

#endif
