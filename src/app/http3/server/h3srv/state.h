#ifndef WIRED_H3SRV_STATE_H
#define WIRED_H3SRV_STATE_H

#include "app/qpack/qpack/dyntable.h"
#include "common/platform/sys/syscall.h"

/** @file
 * RFC 9114 6.2.1 / 7.2.4 / 4.1. HTTP/3 server response-layer state after the
 * 1-RTT handshake: the local control + SETTINGS-first ordering, peer control
 * SETTINGS-first verification, and the request-before-response invariant. */

/** HTTP/3 server response-layer state after the 1-RTT handshake. */
typedef struct {
  u8 settings_sent;      /**< local control opened and SETTINGS emitted first */
  u8 peer_control;       /**< 1 once a peer control stream has been seen */
  u8 peer_settings;      /**< peer SETTINGS-first recorded */
  u8 request_seen;       /**< a request HEADERS has been decoded */
  u8 peer_qpack_encoder; /**< 1 once a peer QPACK encoder stream has been seen
                          */
  u8 peer_qpack_decoder; /**< 1 once a peer QPACK decoder stream has been seen
                          */
  /** RFC 9204 3.2 / 4.3.1: this connection's QPACK dynamic table, the peer's
   * encoder stream instructions (Set Dynamic Table Capacity, Insert...) are
   * applied to (see wired_h3srv_qpack_max_table). Initialised empty
   * (capacity 0) by wired_h3srv_state_init; a peer that never opens an
   * encoder stream or never raises the capacity keeps it at 0, matching
   * RFC 9204 3.2's "no dynamic table" default. */
  quic_qpack_dyn qdyn;
  /** RFC 9204 5 (SETTINGS_QPACK_MAX_TABLE_CAPACITY): the maximum dynamic
   * table capacity (in bytes) this server has advertised to the peer --
   * quic_qpack_capacity_within_limit's own limit argument when validating a
   * received Set Dynamic Table Capacity instruction (9204-032). 0 (this
   * SDK's current default: it never emits a non-zero value in its own
   * SETTINGS) means the peer's encoder may not raise the table past 0
   * either. */
  u64 qpack_max_table_capacity;
} wired_h3srv_state;

/** RFC 9204 3.2: initialise st's dynamic table empty and its own advertised
 * capacity limit -- called once per connection (wired_srvloop_init), mirrors
 * quic_qpack_dyn_init's own single-purpose shape but scoped to the owning
 * wired_h3srv_state.
 * @param st the state to initialise
 * @param max_table_capacity the limit this server advertises via
 *   SETTINGS_QPACK_MAX_TABLE_CAPACITY (0 if none) */
void wired_h3srv_state_init(wired_h3srv_state* st, u64 max_table_capacity);

#endif
