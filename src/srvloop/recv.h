#ifndef QUIC_SRVLOOP_RECV_H
#define QUIC_SRVLOOP_RECV_H

#include "server/server.h"

/* RFC 9001 4 / 5.1 / RFC 9000 17.2 / A.3: open one received server-side
 * datagram. The first byte selects the protection level (Initial / Handshake /
 * 1-RTT); the peer-direction key (CLIENT_HS / CLIENT_AP) is used to open, never
 * the server's own. largest_pn is the largest 1-RTT packet number received so
 * far (0 before any), used to recover the full packet number from its truncated
 * form for the 1-RTT space. On success *level is the QUIC_LEVEL_* the packet was
 * opened at, payload/payload_len the recovered plaintext frames (a view into
 * dgram). Returns 1, or 0 on an unhandled type, a missing peer key, or AEAD
 * failure. */
int quic_srvloop_recv(quic_server *s, u8 *dgram, usz len, u64 largest_pn,
                      int *level, const u8 **payload, usz *payload_len);

#endif
