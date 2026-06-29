#ifndef QUIC_CONNRUNNER_CONNRUNNER_H
#define QUIC_CONNRUNNER_CONNRUNNER_H

#include "io/udp.h"
#include "evloop/evloop.h"
#include "connio/connio.h"
#include "rtxbytes/rtxstore.h"

/* RFC 9000 12 / RFC 9001 4: the top-level connection runner. It binds the
 * abstract steady-state loop (evloop, which only decides) to the real socket
 * (io/udp via udploop) and the real cryptography (connio, which seals/opens).
 * Each iteration drains ready receives, runs the loop's timers and one send
 * decision, then turns that decision into sealed datagrams on the wire. */

#define QUIC_CONNRUNNER_BUF 1500 /* RFC 9000 14: a conservative datagram bound */

typedef struct {
    i64 fd;
    quic_sockaddr_in peer;
    quic_evloop loop;  /* the deciding state machine */
    quic_connio io;    /* the real crypto / frame dispatch */
    quic_rtxbytes rtx; /* RFC 9002 13.3: real frame bytes kept for resend */
    u64 rtx_pn;        /* lost pn captured pre-step, for the resend's bytes */
    int rtx_held;      /* 1 if a lost pn is captured for this send */
    u8 rxbuf[QUIC_CONNRUNNER_BUF];
    u8 txbuf[QUIC_CONNRUNNER_BUF];
} quic_connrunner;

/* Bind the runner to fd and peer; init the loop at `level` (cwnd open,
 * send_len-byte packets) and the connio with the given header parameters. */
void quic_connrunner_init(quic_connrunner *r, i64 fd,
                          const quic_sockaddr_in *peer, int level, u64 cwnd,
                          usz send_len, int is_server, u8 byte0,
                          const u8 *dcid, u8 dcid_len, u64 initial_max_data);

/* The socket-free core of one iteration (RFC 9000 12): with a datagram already
 * in `dgram`/`len` (len 0 = none), drain it, step the loop, and seal the send
 * the loop decided -- recv before step before send. Returns the sealed datagram
 * length in r->txbuf to transmit, or 0. */
usz quic_connrunner_advance(quic_connrunner *r, u64 now, u8 *dgram, usz len);

/* Run one iteration: wait readable, drain a datagram, step the loop, flush any
 * sends -- in that order (RFC 9000 12). `now` is the monotonic time. */
void quic_connrunner_iterate(quic_connrunner *r, u64 now);

/* Repeat iterate until the connection is closed or max_iterations is reached. */
void quic_connrunner_run(quic_connrunner *r, u64 now, usz max_iterations);

#endif
