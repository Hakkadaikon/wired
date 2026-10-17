#include "transport/conn/loop/connio/connio_impl.h"

static int dispatch_all(connio* io, wired_span frames);
static int recv_ready(
    connio* io, const connio_recv_in* in, const initial_keys** keys);
static int validates_address(const connio* io, int level);
static int recv_accept(connio* io, int level, wired_span frames);
static usz violation_close_frame(u8* buf, usz cap);
static usz aead_limit_close_frame(u8* buf, usz cap);
static usz stop_sending_reset_frame(
    u8* buf, usz cap, const framedispatch_state* d);

/* RFC 9000 12.4: walk the recovered payload and dispatch each frame into the
 * receive state. Returns 1 if every frame was handled. */
static int dispatch_all(connio* io, wired_span frames) {
  framewalk      it;
  framewalk_item fr;
  int            ok = 1;
  framewalk_init(&it, frames.p, frames.n);
  while (framewalk_next(&it, &fr))
    ok &= framedispatch_handle(
        &io->disp, fr.type, wired_span_of(fr.start, fr.remaining));
  return ok;
}

/* RFC 9001 4: a level may process a datagram only once its keys are installed
 * and the connloop gate (phase, discarded level) admits it. */
static int recv_ready(
    connio* io, const connio_recv_in* in, const initial_keys** keys) {
  return connloop_on_recv(&io->loop, in->level, in->datagram.n) &&
         keyset_for_level(&io->loop.keys, in->level, keys);
}

/* RFC 9000 8.1: a server validates the client's address upon successfully
 * receiving a Handshake packet, lifting the anti-amplification limit. */
static int validates_address(const connio* io, int level) {
  return io->loop.is_server && level == LEVEL_HANDSHAKE;
}

/* Post-decrypt receive bookkeeping: advance the read PN, lift the amp limit on
 * a server's first Handshake packet (RFC 9000 8.1), then dispatch frames. */
static int recv_accept(connio* io, int level, wired_span frames) {
  io->rx_pn[level]++; /* RFC 9000 12.3: advance only the inbound space */
  if (validates_address(io, level)) connloop_validate(&io->loop);
  return dispatch_all(io, frames);
}

int connio_recv(connio* io, int level, wired_mspan datagram) {
  const initial_keys* keys;
  aes128              hp;
  wired_span          frames;
  connio_recv_in      in = {level, datagram};
  if (!recv_ready(io, &in, &keys)) return 0;
  aes128_init(&hp, keys->hp);
  protect_keys k = {keys, &hp};
  rx_desc      d = {datagram, connio_level_is_initial(level), io->rx_pn[level]};
  if (!rx_packet(&k, &d, &frames)) {
    /* RFC 9001 6.6: this layer only ever runs AES-128-GCM (is_chacha=0). */
    connloop_on_auth_fail(&io->loop, 0);
    return 0;
  }
  return recv_accept(io, level, frames);
}

/* RFC 9000 19.19: encode a transport CONNECTION_CLOSE(PROTOCOL_VIOLATION)
 * frame into buf. Returns bytes written, or 0 on overflow. */
static usz violation_close_frame(u8* buf, usz cap) {
  conn_close_frame cc = {0, ERR_PROTOCOL_VIOLATION, 0, 0, (const u8*)0};
  return frame_put_conn_close(buf, cap, &cc);
}

usz connio_close_on_violation(connio* io, wired_obuf* out) {
  u8             frame[16];
  usz            fl;
  connio_send_in sin;
  if (!io->disp.violation) return 0;
  io->disp.violation = 0;
  fl                 = violation_close_frame(frame, sizeof frame);
  if (!fl) return 0;
  sin = (connio_send_in){LEVEL_ONERTT, wired_span_of(frame, fl)};
  return connio_send(io, &sin, out);
}

/* RFC 9000 19.19: encode a transport CONNECTION_CLOSE(AEAD_LIMIT_REACHED)
 * frame into buf. Returns bytes written, or 0 on overflow. */
static usz aead_limit_close_frame(u8* buf, usz cap) {
  conn_close_frame cc = {0, ERR_AEAD_LIMIT_REACHED, 0, 0, (const u8*)0};
  return frame_put_conn_close(buf, cap, &cc);
}

/* RFC 9001 6.6: if the AEAD integrity limit was reached (recorded by
 * connloop_on_auth_fail), seal a transport CONNECTION_CLOSE carrying
 * AEAD_LIMIT_REACHED as a 1-RTT packet into out and clear the flag. Returns
 * the sealed length, or 0 if the limit was not reached or the seal failed. */
usz connio_close_on_aead_limit(connio* io, wired_obuf* out) {
  u8             frame[16];
  usz            fl;
  connio_send_in sin;
  if (!io->loop.aead_limit) return 0;
  io->loop.aead_limit = 0;
  fl                  = aead_limit_close_frame(frame, sizeof frame);
  if (!fl) return 0;
  sin = (connio_send_in){LEVEL_ONERTT, wired_span_of(frame, fl)};
  return connio_send(io, &sin, out);
}

/* RFC 9000 3.5/19.4: encode a RESET_STREAM echoing a STOP_SENDING's stream
 * ID and error code verbatim. Returns bytes written, or 0 on overflow. */
static usz stop_sending_reset_frame(
    u8* buf, usz cap, const framedispatch_state* d) {
  reset_stream_frame f = {
      d->stop_sending_stream_id, d->stop_sending_error_code, 0};
  return reset_stream_encode(buf, cap, &f);
}

usz connio_send_stop_sending_reset(connio* io, wired_obuf* out) {
  u8             frame[32];
  usz            fl;
  connio_send_in sin;
  if (!io->disp.stop_sending_owed) return 0;
  io->disp.stop_sending_owed = 0;
  fl = stop_sending_reset_frame(frame, sizeof frame, &io->disp);
  if (!fl) return 0;
  sin = (connio_send_in){LEVEL_ONERTT, wired_span_of(frame, fl)};
  return connio_send(io, &sin, out);
}
