#ifndef WIRED_SRVLOOP_RECV_H
#define WIRED_SRVLOOP_RECV_H

#include "common/bytes/span/span.h"
#include "tls/handshake/roles/server/server.h"

/** Opened-payload output: the protection level the packet was opened at and
 * the recovered plaintext frames (a view into the input datagram). */
typedef struct {
  int        level;
  wired_span payload;
} wired_srvloop_recv_out;

/** The received datagram and the largest packet number seen so far in the
 * spaces this open may touch (0 before any), used to recover the full
 * packet number from its truncated wire form (RFC 9000 A.3): largest_pn
 * for the App space (1-RTT and 0-RTT share it, RFC 9000 12.3),
 * hs_largest_pn for the Handshake space. */
typedef struct {
  wired_mspan dgram;
  u64         largest_pn;
  u64         hs_largest_pn;
} wired_srvloop_recv_in;

/* RFC 9001 4 / 5.1 / RFC 9000 17.2 / A.3: open one received server-side
 * datagram. The first byte selects the protection level (Initial / Handshake /
 * 1-RTT); the peer-direction key (CLIENT_HS / CLIENT_AP) is used to open, never
 * the server's own. On success out->level is the LEVEL_* the packet was
 * opened at, out->payload the recovered plaintext frames. Returns 1, or 0 on
 * an unhandled type, a missing peer key, or AEAD failure. */
int wired_srvloop_recv(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out);

#endif
