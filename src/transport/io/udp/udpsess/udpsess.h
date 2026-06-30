#ifndef QUIC_UDPSESS_UDPSESS_H
#define QUIC_UDPSESS_UDPSESS_H

#include "common/platform/sys/syscall.h"
#include "transport/io/socket/io/udptransport.h"

/* RFC 9000 9: connection migration over a single UDP socket. The connection is
 * identified by its CID, so the same socket can switch its send target when the
 * peer's address changes. A new path is fully migrated to only after it is
 * validated (9.3); until then the old path is kept (9.3.3, so it can still be
 * acked). Each path uses a distinct destination CID to avoid linkability across
 * paths (9.5). This drives an existing quic_udp_transport; it opens no new
 * sockets and issues no sendto/recvfrom itself. */

#define QUIC_UDPSESS_PATHS 2

typedef struct {
  u32       peer_addr; /* big-endian (network order); 0 = unset */
  u16       peer_port; /* host order */
  const u8 *dcid;      /* destination CID used on this path (view, not owned) */
  u8        dcid_len;
} quic_udpsess_path;

typedef struct {
  quic_udp_transport *t;
  quic_udpsess_path   paths[QUIC_UDPSESS_PATHS];
  usz active; /* index of the path the transport currently sends to */
} quic_udpsess;

/* Bind a session to an open transport. path 0 is the active path, seeded from
 * the transport's current peer and the given DCID. */
void quic_udpsess_init(
    quic_udpsess *s, quic_udp_transport *t, const u8 *dcid, u8 dcid_len);

/* Record the candidate peer address for a path (RFC 9000 9.3). This does not
 * change the active send target; the old path is retained until migration. */
void quic_udpsess_set_peer(quic_udpsess *s, usz path, u32 addr, u16 port);

/* Associate a destination CID with a path (RFC 9000 9.5). */
void quic_udpsess_set_dcid(
    quic_udpsess *s, usz path, const u8 *dcid, u8 dcid_len);

/* Whether migration to a new path is permitted (RFC 9000 9.3): only once that
 * path has been validated. */
int quic_udpsess_can_migrate(const quic_udpsess *s, int new_path_validated);

/* Switch the transport's send target to `path` (RFC 9000 9.3). Refused unless
 * new_path_validated and the path has a peer address. Returns 1 on migration.
 */
int quic_udpsess_migrate(quic_udpsess *s, usz path, int new_path_validated);

/* The destination CID to use on `path` (RFC 9000 9.5). Writes the view and its
 * length and returns 1; returns 0 for an out-of-range or unset path. */
int quic_udpsess_dcid_for_path(
    const quic_udpsess *s, usz path, const u8 **dcid, u8 *len);

#endif
