#include "transport/conn/loop/connio/connio_impl.h"

static int dispatch_all(connio* io, wired_span frames);
static int recv_ready(
    connio* io, const connio_recv_in* in, const initial_keys** keys);
static int validates_address(const connio* io, int level);
static int recv_accept(connio* io, int level, wired_span frames);

/* RFC 9000 12.4: walk the recovered payload and dispatch each frame into the
 * receive state. Returns 1 if every frame was handled. */
static int dispatch_all(connio* io, wired_span frames) {
  framewalk      it;
  framewalk_item fr;
  int            ok = 1;
  framewalk_init(&it, frames.p, frames.n);
  while (framewalk_next(&it, &fr)) {
    ok &= framedispatch_handle(
        &io->disp, fr.type, wired_span_of(fr.start, fr.remaining));
  }
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
  if (validates_address(io, level)) {
    connloop_validate(&io->loop);
  }
  return dispatch_all(io, frames);
}

int connio_recv(connio* io, int level, wired_mspan datagram) {
  const initial_keys* keys;
  aes128              hp;
  wired_span          frames;
  connio_recv_in      in = {level, datagram};
  if (!recv_ready(io, &in, &keys)) {
    return 0;
  }
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
