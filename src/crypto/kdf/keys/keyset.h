#ifndef QUIC_KEYS_KEYSET_H
#define QUIC_KEYS_KEYSET_H

#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 4: per-protection-level key sets. Levels: 0=Initial, 1=Handshake,
 * 2=1-RTT. Each level holds one quic_initial_keys (AES-128-GCM material) plus
 * an installed flag. */

#define QUIC_LEVEL_INITIAL 0
#define QUIC_LEVEL_HANDSHAKE 1
#define QUIC_LEVEL_ONERTT 2
#define QUIC_KEYSET_LEVELS 3

typedef struct {
  quic_initial_keys keys[QUIC_KEYSET_LEVELS];
  int               installed[QUIC_KEYSET_LEVELS];
} quic_keyset;

/* Clear all levels to not-installed. */
void quic_keyset_init(quic_keyset *state);

/* Install keys at level (0/1/2). Returns 1 ok, 0 if level out of range. */
int quic_keyset_install(
    quic_keyset *state, int level, const quic_initial_keys *keys);

/* Fetch keys for level into *out. Returns 1 if installed, 0 otherwise. */
int quic_keyset_for_level(
    const quic_keyset *state, int level, const quic_initial_keys **out);

#endif
