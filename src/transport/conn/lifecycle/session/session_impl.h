#ifndef TRANSPORT_CONN_LIFECYCLE_SESSION_SESSION_IMPL_H
#define TRANSPORT_CONN_LIFECYCLE_SESSION_SESSION_IMPL_H

/* Internal to the session*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/x25519.h"
#include "transport/conn/lifecycle/session/session.h"
#include "transport/io/socket/net/ipv4.h"
#include "transport/io/socket/net/udp4.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/protect/protect/protect.h"
#include "transport/version/version/version.h"

#define SESSION_CA 0x0a000001u
#define SESSION_SA 0x0a000002u

int session_link_tx(memlink* l, wired_span qpkt, ipv4addrs addrs);
usz session_link_rx(memlink* l, wired_obuf* out, ipv4addrs addrs);
int session_seal_tx(
    session*            s,
    const protect_keys* k,
    u8                  byte0,
    u8                  pn,
    wired_span          payload,
    ipv4addrs           addrs);

#endif
