#ifndef QUIC_SRESETDRIVE_TOKENMAP_H
#define QUIC_SRESETDRIVE_TOKENMAP_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.3 associating a Stateless Reset Token with a connection ID.
 * An endpoint records, per CID it uses to reach a peer, the token the peer
 * advertised, so a later packet can be matched against the right token. */

#define QUIC_SRESETDRIVE_TOKEN   16
#define QUIC_SRESETDRIVE_MAX_CID 20  /* RFC 9000 5.1: CID is at most 20 bytes */
#define QUIC_SRESETDRIVE_CAP     8   /* concurrent CIDs tracked per peer */

typedef struct {
    u8 cid[QUIC_SRESETDRIVE_MAX_CID];
    u8 cid_len;
    u8 token[QUIC_SRESETDRIVE_TOKEN];
} quic_sresetdrive_entry;

typedef struct {
    quic_sresetdrive_entry e[QUIC_SRESETDRIVE_CAP];
    usz count;
} quic_sresetdrive_map;

/* Reset the map to empty. */
void quic_sresetdrive_map_init(quic_sresetdrive_map *m);

/* Record `token` for `cid`. Returns 1 on success, 0 if full or CID too long. */
int quic_sresetdrive_map_add(quic_sresetdrive_map *m,
                             const u8 *cid, u8 cid_len,
                             const u8 token[QUIC_SRESETDRIVE_TOKEN]);

/* On a match, point `*token` at the stored token and return 1; else 0. */
int quic_sresetdrive_map_find(const quic_sresetdrive_map *m,
                              const u8 *cid, u8 cid_len,
                              const u8 **token);

#endif
