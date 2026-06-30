#ifndef QUIC_VERSMGR_AVAIL_H
#define QUIC_VERSMGR_AVAIL_H

#include "common/platform/sys/syscall.h"

/* RFC 9368 5: an endpoint keeps the set of QUIC versions it supports, in
 * preference order, and matches it against a peer's Available Versions to pick
 * a compatible version. */

#define QUIC_VERS_MAX 16

typedef struct {
    usz n;
    u32 versions[QUIC_VERS_MAX]; /* preference order, most preferred first */
} quic_vers_set;

/* Initialise s to this endpoint's supported set (v2 then v1). */
void quic_vers_init(quic_vers_set *s);

/* 1 if s supports version, else 0. */
int quic_vers_supports(const quic_vers_set *s, u32 version);

/* Pick the most-preferred version in s that also appears in peer_versions
 * (peer's Available Versions). Returns 1 with *chosen set, or 0 if none. */
int quic_vers_choose_compatible(const quic_vers_set *s,
                                const u32 *peer_versions, usz n, u32 *chosen);

#endif
