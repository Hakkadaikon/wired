#ifndef QUIC_CONNRUNNER_CONNRUNNER_H
#define QUIC_CONNRUNNER_CONNRUNNER_H

#include "common/bytes/span/span.h"
#include "tls/keys/kuswitch/twogen.h"
#include "transport/conn/cid/retrydrive/reconnect.h"
#include "transport/conn/loop/connio/connio.h"
#include "transport/conn/loop/evloop/evloop.h"
#include "transport/io/socket/io/udp.h"
#include "transport/recovery/rtx/rtxbytes/rtxstore.h"
#include "transport/recovery/rtx/sentmeta/record.h"

/* RFC 9000 12 / RFC 9001 4: the top-level connection runner. It binds the
 * abstract steady-state loop (evloop, which only decides) to the real socket
 * (io/udp via udploop) and the real cryptography (connio, which seals/opens).
 * Each iteration drains ready receives, runs the loop's timers and one send
 * decision, then turns that decision into sealed datagrams on the wire. */

#define QUIC_CONNRUNNER_BUF \
  1500 /* RFC 9000 14: a conservative datagram bound */

typedef struct {
  i64           fd;
  quic_sockaddr peer;
  quic_evloop   loop; /* the deciding state machine */
  quic_connio   io;   /* the real crypto / frame dispatch */
  quic_rtxbytes rtx;  /* RFC 9002 13.3: real frame bytes kept for resend */
  quic_sentmeta sent; /* RFC 9002 A.1: real sent-packet metadata + in-flight */
  u64           rtx_pn; /* lost pn captured pre-step, for the resend's bytes */
  int           rtx_held; /* 1 if a lost pn is captured for this send */
  /* RFC 9001 6: 1-RTT key-update generation state and its driving inputs. */
  quic_kuswitch_state ku;
  u8  ku_secret[QUIC_HKDF_PRK]; /* current generation's app traffic secret */
  u8  ku_phase;         /* RFC 9001 6.2: advertised 1-RTT Key Phase byte0 */
  u64 ku_completed_at;  /* RFC 9001 6.2: pins both 3*PTO clocks; -1 = unset */
  u64 ku_sent_in_phase; /* RFC 9001 6.6: packets sent under current keys */
  int ku_unacked;       /* RFC 9001 6.5: a self update is unacknowledged */
  /* RFC 9000 17.2.5 / 6.2: Retry and Version Negotiation reconnect state. */
  quic_retrydrive_state retry;
  u32 sent_version;   /* RFC 9000 6.2: version of the client's Initial */
  int vn_retry_count; /* RFC 9000 6.2: VN reconnects so far (<=1) */
  u8  rxbuf[QUIC_CONNRUNNER_BUF];
  u8  txbuf[QUIC_CONNRUNNER_BUF];
} quic_connrunner;

/* Everything quic_connrunner_init needs besides the runner and the DCID. */
typedef struct {
  i64                  fd;
  const quic_sockaddr* peer;
  int                  level;
  u64                  cwnd;
  usz                  send_len;
  int                  is_server;
  u8                   byte0;
  u64                  initial_max_data;
} quic_connrunner_init_in;

/* Bind the runner to fd and peer; init the loop at `level` (cwnd open,
 * send_len-byte packets) and the connio with the given header parameters. */
void quic_connrunner_init(
    quic_connrunner* r, quic_span dcid, const quic_connrunner_init_in* in);

/* The socket-free core of one iteration (RFC 9000 12): with a datagram already
 * in `dgram` (empty = none), drain it, step the loop, and seal the send the
 * loop decided -- recv before step before send. Returns the sealed datagram
 * length in r->txbuf to transmit, or 0. */
usz quic_connrunner_advance(quic_connrunner* r, u64 now, quic_mspan dgram);

/* Run one iteration: wait readable, drain a datagram, step the loop, flush any
 * sends -- in that order (RFC 9000 12). `now` is the monotonic time. */
void quic_connrunner_iterate(quic_connrunner* r, u64 now);

/* Repeat iterate until the connection is closed or max_iterations is reached.
 */
void quic_connrunner_run(quic_connrunner* r, u64 now, usz max_iterations);

#endif
