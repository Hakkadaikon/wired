#ifndef QUIC_PATH_PREFADDR_H
#define QUIC_PATH_PREFADDR_H

/* RFC 9000 9.6: migrating to a server's preferred_address requires the new
 * path to be validated and the handshake confirmed. */

/* 1 iff both the new path is validated and the handshake is confirmed. */
int quic_prefaddr_may_migrate(int path_validated, int handshake_confirmed);

/* The preferred_address may carry a connection ID; use it when present. */
int quic_prefaddr_use_cid(int has_preferred_cid);

#endif
