#ifndef QUIC_CONNIO_CONNIO_H
#define QUIC_CONNIO_CONNIO_H

#include "common/bytes/span/span.h"
#include "transport/conn/lifecycle/conn/pnspace.h"
#include "transport/conn/loop/connloop/connloop.h"
#include "transport/conn/pnspace/pnspaces/spaces.h"
#include "transport/packet/frame/framedispatch/dispatch_state.h"
#include "transport/packet/header/packet/header.h"
#include "transport/stream/flow/flow/credit.h"
#include "transport/stream/flow/flow/stream_read.h"

/* RFC 9001 5: connection I/O. connloop gates each send/recv (key availability,
 * monotonic send level, anti-amplification, lifecycle phase); connio carries
 * out the real cryptographic work the gate permits: it seals outbound frames
 * into a protected packet and opens inbound packets, walking the recovered
 * payload frame by frame into the receive state. All policy lives in connloop;
 * connio is the wiring between that decision and the protect/dispatch layers.
 */

typedef struct {
  quic_connloop            loop;   /* state + gating (owns the keyset) */
  quic_stream_read         stream; /* STREAM data sink */
  quic_flow_credit         credit; /* connection flow credit */
  quic_framedispatch_state disp; /* dispatch view over the above + loop.sent */
  u8 dcid[QUIC_MAX_CID_LEN];     /* Destination Connection ID for headers */
  u8 dcid_len;
  u8 byte0;         /* long-header first byte for built packets */
  quic_pnspaces tx; /* RFC 9000 12.3: per-space next send PN */
  u64           rx_pn[QUIC_PNS_COUNT]; /* per-space next expected inbound PN */
} quic_connio;

/* The header parameters for a fresh connio, besides its DCID. */
typedef struct {
  int is_server;
  u8  byte0;
  u64 initial_max_data;
} quic_connio_init_in;

/* Set up an active connection: empty keyset, fresh receive state, the dispatch
 * view wired to drain ACKs into loop.sent, and the given header parameters. */
void quic_connio_init(quic_connio *io, quic_span dcid, const quic_connio_init_in *in);

/* RFC 9001 5: receive one protected datagram at protection `level`. Gates via
 * connloop_on_recv; on permission, fetches the level's keys, opens the packet
 * in place, and dispatches every recovered frame into the receive state.
 * Returns 1 if the packet was processed, 0 if gated out or authentication
 * failed. `datagram` is modified in place (header protection / AEAD). */
int quic_connio_recv(quic_connio *io, int level, quic_mspan datagram);

/* The protection level and frame bytes to seal into a packet. */
typedef struct {
  int       level;
  quic_span frames;
} quic_connio_send_in;

/* RFC 9001 5: send frame bytes at protection `level`. Gates via
 * connloop_on_send; on permission, fetches the level's keys and seals a
 * protected packet into out. Returns the protected length, or 0 if
 * gated out or out is too small. */
usz quic_connio_send(quic_connio *io, const quic_connio_send_in *in, quic_obuf *out);

/* RFC 9000 12.3: the next send packet number for `level`'s own space (peek,
 * does not advance). Each level/space numbers independently from 0. */
u64 quic_connio_tx_next(const quic_connio *io, int level);

/* The next expected inbound packet number for `level`'s own space. */
u64 quic_connio_rx_next(const quic_connio *io, int level);

#endif
