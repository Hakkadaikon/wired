#include "transport/conn/loop/connrunner/connrunner.h"

#include "transport/conn/loop/connrunner/keyupdate.h"
#include "transport/conn/loop/connrunner/pmtudrive.h"
#include "transport/conn/loop/connrunner/reconnect.h"
#include "transport/conn/loop/connrunner/recv.h"
#include "transport/conn/loop/connrunner/send.h"
#include "transport/io/socket/poll/deadline.h"
#include "transport/io/socket/poll/wait.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/io/udp/udploop/txloop.h"

void quic_connrunner_init(
    quic_connrunner* r, quic_span dcid, const quic_connrunner_init_in* in) {
  quic_connio_init_in cin = {in->is_server, in->byte0, in->initial_max_data};
  quic_evloop_init_in ein = {in->level, in->cwnd, in->send_len};
  r->fd                   = in->fd;
  r->peer                 = *in->peer;
  quic_evloop_init(&r->loop, &ein);
  quic_rtxbytes_init(&r->rtx);
  quic_sentmeta_init(&r->sent);
  r->rtx_held = 0;
  quic_connio_init(&r->io, dcid, &cin);
  quic_connrunner_keyupdate_init(r);
  quic_connrunner_reconnect_init(r);
  quic_connrunner_pmtu_init(r);
}

/* RFC 9000 19.7/19.20 via connio.h: a violation flagged while dispatching the
 * just-processed datagram (e.g. a server dispatching NEW_TOKEN, RFC 9000
 * 19.7) outranks the loop's own send choice -- if flush_sends already sent
 * nothing this step, seal the CONNECTION_CLOSE into r->txbuf instead so a
 * protocol violation is never silently dropped for lack of anything else to
 * send. */
static usz advance_close_on_violation(quic_connrunner* r, usz out) {
  quic_obuf ob;
  if (out) return out;
  ob = quic_obuf_of(r->txbuf, sizeof(r->txbuf));
  return quic_connio_close_on_violation(&r->io, &ob);
}

/* RFC 8899: reconcile the outstanding probe against this round's ack/loss
 * results, mirroring quic_connrunner_track_acks/track_loss's own detection. */
static void advance_pmtu_reconcile(quic_connrunner* r, u64 now) {
  u64 lost[QUIC_SENTMETA_CAP];
  usz n;
  quic_connrunner_track_loss_ex(r, now, lost, &n);
  quic_connrunner_pmtu_reconcile(r, lost, n);
}

/* RFC 8899 3.2/5.1: once the handshake is confirmed and nothing else was
 * chosen to send this iteration, opportunistically send one PLPMTU probe as
 * its own datagram -- a probe must exceed the normal PLPMTU, so it is never
 * coalesced with a regular packet built to send_len. */
static usz advance_pmtu_probe(quic_connrunner* r, usz out) {
  usz sealed;
  if (out || !r->loop.gate.handshake_confirmed) return out;
  {
    quic_obuf ob = quic_obuf_of(r->txbuf, sizeof(r->txbuf));
    sealed       = quic_connrunner_pmtu_build_probe(r, &ob);
  }
  return sealed;
}

/* RFC 9000 12: the fixed-order core of one iteration, with the datagram already
 * in hand (or empty). Drain receives, step the loop (timers + one send
 * decision), then seal whatever the loop chose -- recv before step before send.
 * Returns the sealed datagram length to transmit, or 0. Socket-free. */
usz quic_connrunner_advance(quic_connrunner* r, u64 now, quic_mspan dgram) {
  u64 sent_before;
  int kind;
  usz out;
  if (dgram.n) quic_connrunner_process_datagram(r, dgram);
  quic_connrunner_track_acks(r);          /* RFC 9002 A.2.2: drop acked bytes */
  kind = quic_connrunner_pending_kind(r); /* before step clears it */
  quic_connrunner_capture_rtx(r);         /* lost pn before step drains it */
  advance_pmtu_reconcile(r, now);         /* RFC 8899: probe ack/loss */
  sent_before = r->loop.next_pn;
  quic_evloop_step(&r->loop, now);
  out = quic_connrunner_flush_sends(r, sent_before, kind);
  out = advance_close_on_violation(r, out);
  {
    quic_connrunner_sent_in sin = {now, kind, out};
    quic_connrunner_track_sent(r, &sin); /* RFC 9002 A.1: in-flight */
  }
  out = advance_pmtu_probe(r, out);
  quic_connrunner_pmtu_track_sent(r, now, out); /* RFC 9002 6.1 visibility */
  return out;
}

/* Append an armed timer's deadline to ds (RFC 9002 6: unarmed timers do not
 * bound the wait). */
static void push_armed(const quic_evloop_timer* t, u64* ds, usz* n) {
  if (t->armed) ds[(*n)++] = t->deadline;
}

/* RFC 9002 6.2 / 6.1 / RFC 9000 10.1: the next wakeup is the soonest armed
 * timer. Returns 0 if none armed. */
static u64 next_deadline(const quic_connrunner* r) {
  u64 ds[3];
  usz n = 0;
  push_armed(&r->loop.pto, ds, &n);
  push_armed(&r->loop.loss, ds, &n);
  push_armed(&r->loop.idle, ds, &n);
  return quic_poll_min_deadline(ds, n);
}

/* Milliseconds to wait until the next deadline; 0 means block (no timer). */
static u64 wait_timeout(const quic_connrunner* r, u64 now) {
  u64 dl = next_deadline(r);
  if (!dl) return 0;
  return quic_poll_timeout_until(now, dl);
}

/* Wait for and read one datagram into rxbuf; returns its length, or 0. */
static usz wait_and_recv(quic_connrunner* r, u64 now) {
  i64 got;
  if (quic_poll_wait_readable(r->fd, wait_timeout(r, now)) != 1) return 0;
  got = wired_udp_recvfrom(
      r->fd, quic_mspan_of(r->rxbuf, sizeof(r->rxbuf)), &r->peer);
  if (got <= 0) return 0;
  return (usz)got;
}

void quic_connrunner_iterate(quic_connrunner* r, u64 now) {
  usz len = wait_and_recv(r, now);
  usz out = quic_connrunner_advance(r, now, quic_mspan_of(r->rxbuf, len));
  if (out) {
    usz         one = out;
    quic_udpdst dst = {r->fd, &r->peer};
    quic_pktsrc src = {r->txbuf, &one, 1};
    quic_obuf   ob  = quic_obuf_of(r->rxbuf, sizeof(r->rxbuf));
    quic_udploop_tx(&dst, &src, &ob);
  }
}

/* Progress halts once closed; otherwise iterate up to the bound. */
static int run_done(const quic_connrunner* r, usz i, usz max) {
  return i >= max || r->loop.gate.phase == QUIC_CONNLOOP_CLOSED;
}

void quic_connrunner_run(quic_connrunner* r, u64 now, usz max_iterations) {
  usz i;
  for (i = 0; !run_done(r, i, max_iterations); i++)
    quic_connrunner_iterate(r, now);
}
