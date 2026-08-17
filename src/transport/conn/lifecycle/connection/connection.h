#ifndef CONNECTION_CONNECTION_H
#define CONNECTION_CONNECTION_H

#include "common/bytes/span/span.h"
#include "crypto/kdf/keys/keyset.h"
#include "transport/conn/lifecycle/conn/conn.h"
#include "transport/io/socket/net/memlink.h"
#include "transport/packet/frame/pipeline/framewalk.h"

/* RFC 9000 12 / RFC 9001 4: a connection object that drives send/receive.
 * It bundles a per-level keyset, the phase + packet-number-space machine, the
 * in-memory link, the connection ID, and the role, so a caller can push one
 * protected packet and pull one back without touching the protection
 * pipeline directly. */
/** RFC 9000 12 / RFC 9001 4: a connection's keyset, phase/packet-number-space
 * machine, link, connection ID and role, plus its receive scratch buffer. */
typedef struct {
  keyset   keys;
  conn     conn;
  memlink* link;
  u8       dcid[8];
  int      is_server;
  /** Scratch for connection_recv's unprotect: per-instance so two
   * connections stepping concurrently (e.g. from separate threads) never
   * share one buffer. The returned plaintext view stays valid until this
   * connection's next recv, same lifetime rule as before this became a
   * member. */
  u8 rxbuf[MEMLINK_MTU];
} connection;

/** Everything connection_init needs besides the connection. */
typedef struct {
  const u8* dcid; /* [8] */
  memlink*  link;
  int       is_server;
} connection_init_in;

/* Initialize a connection over `in->link` with the shared DCID and role. The
 * keyset starts empty; no level can send until keys are installed. */
void connection_init(connection* c, const connection_init_in* in);

/* Assemble and protect one packet of `frames` at protection `level`
 * (LEVEL_*), pushing it onto the link. Returns 1 on success, 0 if the
 * level's keys are not installed or assembly fails. */
int connection_send(connection* c, int level, wired_span frames);

/* Pull one packet at `level` from the link, unprotect it, and initialize
 * `iter` over its plaintext frames. Returns 1 on success, 0 if nothing valid
 * was available or the level's keys are not installed. */
int connection_recv(connection* c, int level, framewalk* iter);

#endif
