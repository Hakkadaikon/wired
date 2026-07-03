#include "transport/conn/loop/connio/connio.h"

#include "crypto/kdf/keys/keyset.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/packet/frame/pipeline/rxpacket.h"
#include "transport/packet/frame/pipeline/txpacket.h"

/* RFC 9000 17.2: the Initial level carries a Token (17.2.2); Handshake and the
 * long-header pipeline form used for 1-RTT here do not (17.2.4). */
static int level_is_initial(int level) { return level == QUIC_LEVEL_INITIAL; }

/* RFC 9000 17.2: byte0 long-header form + Initial (0xc3) or Handshake (0xe3)
 * type bits, with a 4-byte packet number (low bits forced by the builder). */
static u8 level_byte0(int level) {
  return level_is_initial(level) ? 0xc3 : 0xe3;
}

void quic_connio_init(
    quic_connio *io, quic_span dcid, const quic_connio_init_in *in) {
  usz i;
  quic_connloop_init(&io->loop, in->is_server);
  quic_stream_read_init(&io->stream);
  quic_flow_credit_init(&io->credit, in->initial_max_data);
  io->disp.stream        = &io->stream;
  io->disp.sent          = &io->loop.sent;
  io->disp.credit        = &io->credit;
  io->disp.ack_eliciting = 0;
  io->disp.close         = 0;
  io->disp.has_ack       = 0;
  io->byte0              = in->byte0;
  io->dcid_len           = (u8)dcid.n;
  quic_pnspaces_init(&io->tx);
  for (i = 0; i < QUIC_PNS_COUNT; i++) io->rx_pn[i] = 0;
  for (i = 0; i < dcid.n; i++) io->dcid[i] = dcid.p[i];
}

/* RFC 9000 12.3: a protection level and its packet number space share the same
 * index (Initial=0, Handshake=1, 1-RTT/Application=2). */
u64 quic_connio_tx_next(const quic_connio *io, int level) {
  return io->tx.pn.next[level];
}

u64 quic_connio_rx_next(const quic_connio *io, int level) {
  return io->rx_pn[level];
}

/* RFC 9001 4: a level may send only once its keys are installed and the
 * connloop gate (level monotonicity, anti-amp, phase) admits the packet. */
static int send_ready(
    quic_connio               *io,
    const quic_connio_send_in *in,
    const quic_initial_keys  **keys) {
  /* ponytail: ack-eliciting hard-set to 1; frames here always elicit (STREAM/
   * PING). Classify frames[0] if a non-eliciting-only send is ever needed.
   * RFC 9000 12.3: gate with the SELECTED space's own next packet number. */
  quic_connloop_send_in sin = {
      in->level, 1, quic_connio_tx_next(io, in->level), in->frames.n};
  return quic_connloop_on_send(&io->loop, &sin) &&
         quic_keyset_for_level(&io->loop.keys, in->level, keys);
}

usz quic_connio_send(
    quic_connio *io, const quic_connio_send_in *in, quic_obuf *out) {
  const quic_initial_keys *keys;
  quic_aes128              hp;
  usz                      n;
  if (!send_ready(io, in, &keys)) return 0;
  quic_aes128_init(&hp, keys->hp);
  quic_protect_keys k    = {keys, &hp};
  quic_span         none = quic_span_of((const u8 *)0, 0);
  quic_tx_desc      t    = {
      level_byte0(in->level),
      quic_span_of(io->dcid, io->dcid_len),
      none,
      level_is_initial(in->level),
      none,
      quic_connio_tx_next(io, in->level),
      in->frames};
  n = quic_tx_packet(&k, &t, quic_mspan_of(out->p, out->cap));
  if (n) {
    quic_pnspaces_next_pn(&io->tx, in->level); /* advance only on success */
    out->len = n;
  }
  return n;
}

/* RFC 9000 12.4: walk the recovered payload and dispatch each frame into the
 * receive state. Returns 1 if every frame was handled. */
static int dispatch_all(quic_connio *io, quic_span frames) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 ok = 1;
  quic_framewalk_init(&it, frames.p, frames.n);
  while (quic_framewalk_next(&it, &fr))
    ok &= quic_framedispatch_handle(
        &io->disp, fr.type, quic_span_of(fr.start, fr.remaining));
  return ok;
}

/* The protection level and datagram quic_connio_recv opens. */
typedef struct {
  int        level;
  quic_mspan datagram;
} connio_recv_in;

/* RFC 9001 4: a level may process a datagram only once its keys are installed
 * and the connloop gate (phase, discarded level) admits it. */
static int recv_ready(
    quic_connio *io, const connio_recv_in *in, const quic_initial_keys **keys) {
  return quic_connloop_on_recv(&io->loop, in->level, in->datagram.n) &&
         quic_keyset_for_level(&io->loop.keys, in->level, keys);
}

/* RFC 9000 8.1: a server validates the client's address upon successfully
 * receiving a Handshake packet, lifting the anti-amplification limit. */
static int validates_address(const quic_connio *io, int level) {
  return io->loop.is_server && level == QUIC_LEVEL_HANDSHAKE;
}

/* Post-decrypt receive bookkeeping: advance the read PN, lift the amp limit on
 * a server's first Handshake packet (RFC 9000 8.1), then dispatch frames. */
static int recv_accept(quic_connio *io, int level, quic_span frames) {
  io->rx_pn[level]++; /* RFC 9000 12.3: advance only the inbound space */
  if (validates_address(io, level)) quic_connloop_validate(&io->loop);
  return dispatch_all(io, frames);
}

int quic_connio_recv(quic_connio *io, int level, quic_mspan datagram) {
  const quic_initial_keys *keys;
  quic_aes128              hp;
  quic_span                frames;
  connio_recv_in           in = {level, datagram};
  if (!recv_ready(io, &in, &keys)) return 0;
  quic_aes128_init(&hp, keys->hp);
  quic_protect_keys k = {keys, &hp};
  quic_rx_desc      d = {datagram, level_is_initial(level)};
  if (!quic_rx_packet(&k, &d, &frames)) return 0;
  return recv_accept(io, level, frames);
}
