#ifndef QUIC_KEYS_KEYSET_H
#define QUIC_KEYS_KEYSET_H

#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/tls/initial.h"

/**
 * @file
 * RFC 9001 4: per-protection-level key sets. Levels: 0=Initial, 1=Handshake,
 * 2=1-RTT. Each level holds one quic_initial_keys (AES-128-GCM material) plus
 * an installed flag.
 */

#define QUIC_LEVEL_INITIAL 0   /**< Initial packet protection level */
#define QUIC_LEVEL_HANDSHAKE 1 /**< Handshake packet protection level */
#define QUIC_LEVEL_ONERTT 2    /**< 1-RTT packet protection level */
#define QUIC_KEYSET_LEVELS 3   /**< number of protection levels */

/**
 * Per-protection-level key store: one AES-128-GCM key set per level plus an
 * installed flag.
 */
typedef struct {
  quic_initial_keys keys[QUIC_KEYSET_LEVELS]; /**< key/iv/hp per level */
  int installed[QUIC_KEYSET_LEVELS]; /**< 1 once keys[level] is valid */
} quic_keyset;

/**
 * Clear all levels to not-installed.
 *
 * @param state key set to reset
 */
void quic_keyset_init(quic_keyset *state);

/**
 * Install keys at level (0/1/2).
 *
 * @param state key set to update
 * @param level protection level (QUIC_LEVEL_*)
 * @param keys  key material copied into the set
 * @return 1 ok, 0 if level out of range.
 */
int quic_keyset_install(
    quic_keyset *state, int level, const quic_initial_keys *keys);

/**
 * Fetch keys for level into *out.
 *
 * *out points into state; it stays valid while state lives and the level is
 * not overwritten.
 *
 * @param state key set to query
 * @param level protection level (QUIC_LEVEL_*)
 * @param out   receives a pointer to the installed keys
 * @return 1 if installed, 0 otherwise.
 */
int quic_keyset_for_level(
    const quic_keyset *state, int level, const quic_initial_keys **out);

#endif
