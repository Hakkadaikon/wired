#include "connrunner/connrunner.h"
#include "connrunner/recv.h"
#include "connrunner/send.h"
#include "connrunner/keyupdate.h"
#include "connrunner/reconnect.h"
#include "poll/deadline.h"
#include "poll/wait.h"
#include "udploop/rxloop.h"
#include "udploop/txloop.h"

void quic_connrunner_init(quic_connrunner *r, i64 fd,
                          const quic_sockaddr_in *peer, int level, u64 cwnd,
                          usz send_len, int is_server, u8 byte0,
                          const u8 *dcid, u8 dcid_len, u64 initial_max_data)
{
    r->fd = fd;
    r->peer = *peer;
    quic_evloop_init(&r->loop, level, cwnd, send_len);
    quic_rtxbytes_init(&r->rtx);
    quic_sentmeta_init(&r->sent);
    r->rtx_held = 0;
    quic_connio_init(&r->io, is_server, byte0, dcid, dcid_len,
                     initial_max_data);
    quic_connrunner_keyupdate_init(r);
    quic_connrunner_reconnect_init(r);
}

/* RFC 9000 12: the fixed-order core of one iteration, with the datagram already
 * in hand (or len 0). Drain receives, step the loop (timers + one send
 * decision), then seal whatever the loop chose -- recv before step before send.
 * Returns the sealed datagram length to transmit, or 0. Socket-free. */
usz quic_connrunner_advance(quic_connrunner *r, u64 now, u8 *dgram, usz len)
{
    u64 sent_before;
    int kind;
    usz out;
    if (len) quic_connrunner_process_datagram(r, dgram, len);
    quic_connrunner_track_acks(r);          /* RFC 9002 A.2.2: drop acked bytes */
    kind = quic_connrunner_pending_kind(r); /* before step clears it */
    quic_connrunner_capture_rtx(r);         /* lost pn before step drains it */
    quic_connrunner_track_loss(r, now);     /* RFC 9002 6.1: real lost pn */
    sent_before = r->loop.next_pn;
    quic_evloop_step(&r->loop, now);
    out = quic_connrunner_flush_sends(r, sent_before, kind);
    quic_connrunner_track_sent(r, now, kind, out); /* RFC 9002 A.1: in-flight */
    return out;
}

/* Append an armed timer's deadline to ds (RFC 9002 6: unarmed timers do not
 * bound the wait). */
static void push_armed(const quic_evloop_timer *t, u64 *ds, usz *n)
{
    if (t->armed) ds[(*n)++] = t->deadline;
}

/* RFC 9002 6.2 / 6.1 / RFC 9000 10.1: the next wakeup is the soonest armed
 * timer. Returns 0 if none armed. */
static u64 next_deadline(const quic_connrunner *r)
{
    u64 ds[3];
    usz n = 0;
    push_armed(&r->loop.pto, ds, &n);
    push_armed(&r->loop.loss, ds, &n);
    push_armed(&r->loop.idle, ds, &n);
    return quic_poll_min_deadline(ds, n);
}

/* Milliseconds to wait until the next deadline; 0 means block (no timer). */
static u64 wait_timeout(const quic_connrunner *r, u64 now)
{
    u64 dl = next_deadline(r);
    if (!dl) return 0;
    return quic_poll_timeout_until(now, dl);
}

/* Wait for and read one datagram into rxbuf; returns its length, or 0. */
static usz wait_and_recv(quic_connrunner *r, u64 now)
{
    i64 got;
    if (quic_poll_wait_readable(r->fd, wait_timeout(r, now)) != 1) return 0;
    got = quic_udp_recvfrom(r->fd, r->rxbuf, sizeof(r->rxbuf), &r->peer);
    if (got <= 0) return 0;
    return (usz)got;
}

void quic_connrunner_iterate(quic_connrunner *r, u64 now)
{
    usz len = wait_and_recv(r, now);
    usz out = quic_connrunner_advance(r, now, r->rxbuf, len);
    if (out) {
        usz one = out;
        quic_udploop_tx(r->fd, &r->peer, r->txbuf, &one, 1,
                        r->rxbuf, sizeof(r->rxbuf));
    }
}

/* Progress halts once closed; otherwise iterate up to the bound. */
static int run_done(const quic_connrunner *r, usz i, usz max)
{
    return i >= max || r->loop.gate.phase == QUIC_CONNLOOP_CLOSED;
}

void quic_connrunner_run(quic_connrunner *r, u64 now, usz max_iterations)
{
    usz i;
    for (i = 0; !run_done(r, i, max_iterations); i++)
        quic_connrunner_iterate(r, now);
}
