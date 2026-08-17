#ifndef QUIC_SRESETDRIVE_TOKENMAP_H
#define QUIC_SRESETDRIVE_TOKENMAP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 10.3 associating a Stateless Reset Token with a connection ID.
 * An endpoint records, per CID it uses to reach a peer, the token the peer
 * advertised, so a later packet can be matched against the right token. */

#define QUIC_SRESETDRIVE_TOKEN 16
#define QUIC_SRESETDRIVE_MAX_CID                                        \
  20                           /* RFC 9000 5.1: CID is at most 20 bytes \
                                */
#define QUIC_SRESETDRIVE_CAP 8 /* concurrent CIDs tracked per peer */

/** One connection ID's remembered Stateless Reset Token (RFC 9000 10.3). */
typedef struct {
  u8 cid[QUIC_SRESETDRIVE_MAX_CID];
  u8 cid_len;
  u8 token[QUIC_SRESETDRIVE_TOKEN];
} sresetdrive_entry;

/** The set of CID-to-token entries tracked for one peer. */
typedef struct {
  sresetdrive_entry e[QUIC_SRESETDRIVE_CAP];
  usz               count;
} sresetdrive_map;

/* Reset the map to empty. */
void sresetdrive_map_init(sresetdrive_map* m);

/* Record `token` for `cid`. Returns 1 on success, 0 if full or CID too long. */
int sresetdrive_map_add(
    sresetdrive_map* m, wired_span cid, const u8 token[QUIC_SRESETDRIVE_TOKEN]);

/* On a match, point `*token` at the stored token and return 1; else 0. */
int sresetdrive_map_find(
    const sresetdrive_map* m, wired_span cid, const u8** token);

#endif
