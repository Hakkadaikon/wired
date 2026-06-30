#ifndef QUIC_MANAGE_LINKABILITY_H
#define QUIC_MANAGE_LINKABILITY_H

#include "common/platform/sys/syscall.h"

/* RFC 9312 5.3: an on-path observer links a connection's activity by its
 * connection ID. Changing the connection ID breaks that linkability; an
 * observer can still link across a migration if the connection ID is
 * carried over unchanged. */

/* True if the connection ID changed, breaking observer linkability. */
int quic_linkability_broken(u64 old_cid, u64 new_cid);

/* True if a migration happened without changing the connection ID, leaving
 * the endpoint linkable across the migration. */
int quic_linkability_at_risk(int migrated, int cid_changed);

#endif
