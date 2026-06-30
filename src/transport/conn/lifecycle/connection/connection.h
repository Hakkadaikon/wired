#ifndef QUIC_CONNECTION_CONNECTION_H
#define QUIC_CONNECTION_CONNECTION_H

#include "crypto/kdf/keys/keyset.h"
#include "transport/conn/lifecycle/conn/conn.h"
#include "transport/io/socket/net/memlink.h"
#include "transport/packet/frame/pipeline/framewalk.h"

/* RFC 9000 12 / RFC 9001 4: a connection object that drives send/receive.
 * It bundles a per-level keyset, the phase + packet-number-space machine, the
 * in-memory link, the connection ID, and the role, so a caller can push one
 * protected packet and pull one back without touching the protection
 * pipeline directly. */
typedef struct {
    quic_keyset keys;
    quic_conn conn;
    quic_memlink *link;
    u8 dcid[8];
    int is_server;
} quic_connection;

/* Initialize a connection over `link` with the shared DCID and role. The
 * keyset starts empty; no level can send until keys are installed. */
void quic_connection_init(quic_connection *c, const u8 dcid[8],
                          quic_memlink *link, int is_server);

/* Assemble and protect one packet of `frames` at protection `level`
 * (QUIC_LEVEL_*), pushing it onto the link. Returns 1 on success, 0 if the
 * level's keys are not installed or assembly fails. */
int quic_connection_send(quic_connection *c, int level,
                         const u8 *frames, usz len);

/* Pull one packet at `level` from the link, unprotect it, and initialize
 * `iter` over its plaintext frames. Returns 1 on success, 0 if nothing valid
 * was available or the level's keys are not installed. */
int quic_connection_recv(quic_connection *c, int level, quic_framewalk *iter);

#endif
