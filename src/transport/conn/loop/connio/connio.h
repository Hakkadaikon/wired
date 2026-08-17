#ifndef CONNIO_CONNIO_H
#define CONNIO_CONNIO_H

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

/** RFC 9001 5: connection I/O state -- the gating loop, receive sinks, the
 * dispatch view, our DCID/header byte, and per-space send/receive packet
 * numbers. */
typedef struct {
  connloop            loop;   /* state + gating (owns the keyset) */
  stream_read         stream; /* STREAM data sink */
  flow_credit         credit; /* connection flow credit */
  framedispatch_state disp;   /* dispatch view over the above + loop.sent */
  u8       dcid[WIRED_MAX_CID_LEN]; /* Destination Connection ID for headers */
  u8       dcid_len;
  u8       byte0;            /* long-header first byte for built packets */
  pnspaces tx;               /* RFC 9000 12.3: per-space next send PN */
  u64      rx_pn[PNS_COUNT]; /* per-space next expected inbound PN */
} connio;

/** The header parameters for a fresh connio, besides its DCID. */
typedef struct {
  int is_server;
  u8  byte0;
  u64 initial_max_data;
} connio_init_in;

/* Set up an active connection: empty keyset, fresh receive state, the dispatch
 * view wired to drain ACKs into loop.sent, and the given header parameters. */
void connio_init(connio* io, wired_span dcid, const connio_init_in* in);

/* RFC 9001 5: receive one protected datagram at protection `level`. Gates via
 * connloop_on_recv; on permission, fetches the level's keys, opens the packet
 * in place, and dispatches every recovered frame into the receive state.
 * Returns 1 if the packet was processed, 0 if gated out or authentication
 * failed. `datagram` is modified in place (header protection / AEAD). */
int connio_recv(connio* io, int level, wired_mspan datagram);

/** The protection level and frame bytes to seal into a packet. */
typedef struct {
  int        level;
  wired_span frames;
} connio_send_in;

/* RFC 9001 5: send frame bytes at protection `level`. Gates via
 * connloop_on_send; on permission, fetches the level's keys and seals a
 * protected packet into out. Returns the protected length, or 0 if
 * gated out or out is too small. */
usz connio_send(connio* io, const connio_send_in* in, wired_obuf* out);

/* RFC 9000 12.3: the next send packet number for `level`'s own space (peek,
 * does not advance). Each level/space numbers independently from 0. */
u64 connio_tx_next(const connio* io, int level);

/* The next expected inbound packet number for `level`'s own space. */
u64 connio_rx_next(const connio* io, int level);

/* RFC 9000 19.7/19.20 via 12.4: if the last dispatched frame set
 * disp.violation (a server received NEW_TOKEN or HANDSHAKE_DONE), seal a
 * transport CONNECTION_CLOSE carrying PROTOCOL_VIOLATION as a 1-RTT packet
 * into out and clear the flag. Returns the sealed length, or 0 if no
 * violation was pending or the seal failed (out too small / no 1-RTT key). */
usz connio_close_on_violation(connio* io, wired_obuf* out);

/* RFC 9001 6.6: if a received packet's AEAD authentication failures have
 * reached the integrity limit (tracked in loop.auth_fail_count via
 * connloop_on_auth_fail, one call per failed connio_recv), seal a
 * transport CONNECTION_CLOSE carrying AEAD_LIMIT_REACHED as a 1-RTT packet
 * into out and clear the pending flag. Returns the sealed length, or 0 if
 * the limit was not reached or the seal failed (out too small / no 1-RTT
 * key). */
usz connio_close_on_aead_limit(connio* io, wired_obuf* out);

/* RFC 9000 3.5: if the last dispatched frame set disp.stop_sending_owed (a
 * STOP_SENDING arrived), seal a RESET_STREAM echoing its stream ID and error
 * code verbatim as a 1-RTT packet into out and clear the flag. final_size is
 * 0 (the send side has not tracked any bytes as sent on this path). Returns
 * the sealed length, or 0 if none was owed or the seal failed. */
usz connio_send_stop_sending_reset(connio* io, wired_obuf* out);

#endif
