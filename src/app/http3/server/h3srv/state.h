#ifndef QUIC_H3SRV_STATE_H
#define QUIC_H3SRV_STATE_H

#include "common/platform/sys/syscall.h"

/** @file
 * RFC 9114 6.2.1 / 7.2.4 / 4.1. HTTP/3 server response-layer state after the
 * 1-RTT handshake: the local control + SETTINGS-first ordering, peer control
 * SETTINGS-first verification, and the request-before-response invariant. */

/** HTTP/3 server response-layer state after the 1-RTT handshake. */
typedef struct {
  u8 settings_sent; /**< local control opened and SETTINGS emitted first */
  u8 peer_control;  /**< 1 once a peer control stream has been seen */
  u8 peer_settings; /**< peer SETTINGS-first recorded */
  u8 request_seen;  /**< a request HEADERS has been decoded */
} quic_h3srv_state;

#endif
