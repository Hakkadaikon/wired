#ifndef VERSMGR_AVAIL_H
#define VERSMGR_AVAIL_H

#include "common/platform/sys/syscall.h"
#include "transport/version/version/version.h"

/* RFC 9368 5: an endpoint keeps the set of QUIC versions it supports, in
 * preference order, and matches it against a peer's Available Versions to pick
 * a compatible version. */

#define VERS_MAX 16

typedef struct {
  usz n;
  u32 versions[VERS_MAX]; /* preference order, most preferred first */
} vers_set;

/* RFC 9308 13: initialise s to the WIRED_VERSIONS_* bits in mask, in the
 * v2-then-v1 preference order; 0 means every supported version. */
void vers_init_mask(vers_set* s, u32 mask);

/* 1 if s supports version, else 0. */
int vers_supports(const vers_set* s, u32 version);

#endif
