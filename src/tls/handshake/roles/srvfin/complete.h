#ifndef QUIC_SRVFIN_COMPLETE_H
#define QUIC_SRVFIN_COMPLETE_H

#include "crypto/kdf/keys/keyset.h"
#include "tls/keys/schedule_drive/keyschedule.h"

/* RFC 9001 4.1.2: after the client Finished verifies, the server completes
 * the handshake: derive the application (1-RTT) secrets from the transcript
 * including the client Finished, install the 1-RTT key set, and mark the
 * handshake confirmed. */

typedef struct {
  quic_keysched *sched;
  quic_keyset   *keys;
  int            confirmed;
} quic_srvfin_state;

void quic_srvfin_state_init(
    quic_srvfin_state *s, quic_keysched *sched, quic_keyset *keys);

/* Advance the key schedule to Master over the final transcript (the handshake
 * messages through the client Finished), install the server 1-RTT keys, and
 * confirm. Returns 1 on success, 0 on a key schedule order violation (no keys
 * installed, not confirmed).
 *
 * The application secrets are Derive-Secret(Master, ..., transcript), which
 * hashes the raw messages internally, so this takes the raw transcript bytes
 * and length, not a precomputed hash. */
int quic_srvfin_complete(
    quic_srvfin_state *s, const u8 *final_transcript, usz final_transcript_len);

#endif
