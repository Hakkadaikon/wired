#include "transport/conn/loop/connio/connio_impl.h"

static u8   level_byte0(int level);
static void connio_disp_init(connio* io);
static int  pn_space_ready(const connio* io, int level);
static int  send_ready(
    connio* io, const connio_send_in* in, const initial_keys** keys);

/* RFC 9000 17.2: the Initial level carries a Token (17.2.2); Handshake and the
 * long-header pipeline form used for 1-RTT here do not (17.2.4). */
int connio_level_is_initial(int level) { return level == LEVEL_INITIAL; }

/* RFC 9000 17.2: byte0 long-header form + Initial (0xc3) or Handshake (0xe3)
 * type bits, with a 4-byte packet number (low bits forced by the builder). */
static u8 level_byte0(int level) {
  return connio_level_is_initial(level) ? 0xc3 : 0xe3;
}

/* Point the frame dispatcher at io's stream/sent/credit state and clear
 * every per-packet flag it reports. */
static void connio_disp_init(connio* io) {
  io->disp.stream            = &io->stream;
  io->disp.sent              = &io->loop.sent;
  io->disp.credit            = &io->credit;
  io->disp.ack_eliciting     = 0;
  io->disp.close             = 0;
  io->disp.has_ack           = 0;
  io->disp.has_datagram      = 0;
  io->disp.violation         = 0;
  io->disp.stop_sending_owed = 0;
  io->disp.has_reset_stream  = 0;
}

void connio_init(connio* io, wired_span dcid, const connio_init_in* in) {
  usz i;
  connloop_init(&io->loop, in->is_server);
  stream_read_init(&io->stream);
  flow_credit_init(&io->credit, in->initial_max_data);
  connio_disp_init(io);
  io->byte0    = in->byte0;
  io->dcid_len = (u8)dcid.n;
  pnspaces_init(&io->tx);
  for (i = 0; i < PNS_COUNT; i++) {
    io->rx_pn[i] = 0;
  }
  for (i = 0; i < dcid.n; i++) {
    io->dcid[i] = dcid.p[i];
  }
}

/* RFC 9000 12.3: a protection level and its packet number space share the same
 * index (Initial=0, Handshake=1, 1-RTT/Application=2). */
u64 connio_tx_next(const connio* io, int level) {
  return io->tx.pn.next[level];
}

u64 connio_rx_next(const connio* io, int level) { return io->rx_pn[level]; }

/* RFC 9000 12.3: once a space has issued its highest legal packet number
 * (2^62-1), the sender must stop sending in it -- silently, without a
 * CONNECTION_CLOSE. Checked ahead of the other send gates so an exhausted
 * space never reaches connloop_on_send. */
static int pn_space_ready(const connio* io, int level) {
  return !pnspaces_exhausted(&io->tx, level);
}

/* RFC 9001 4: a level may send only once its keys are installed and the
 * connloop gate (level monotonicity, anti-amp, phase) admits the packet. */
static int send_ready(
    connio* io, const connio_send_in* in, const initial_keys** keys) {
  /* RFC 9002 2: ack-eliciting iff a sent frame is (not ACK/PADDING/CLOSE).
   * RFC 9000 12.3: gate with the SELECTED space's own next packet number. */
  connloop_send_in sin = {
      in->level, framewalk_ack_eliciting(in->frames),
      connio_tx_next(io, in->level), in->frames.n};
  if (!pn_space_ready(io, in->level)) {
    return 0;
  }
  return connloop_on_send(&io->loop, &sin) &&
         keyset_for_level(&io->loop.keys, in->level, keys);
}

usz connio_send(connio* io, const connio_send_in* in, wired_obuf* out) {
  const initial_keys* keys;
  aes128              hp;
  usz                 n;
  if (!send_ready(io, in, &keys)) {
    return 0;
  }
  aes128_init(&hp, keys->hp);
  protect_keys k    = {keys, &hp};
  wired_span   none = wired_span_of((const u8*)0, 0);
  tx_desc      t    = {
      level_byte0(in->level),
      wired_span_of(io->dcid, io->dcid_len),
      none,
      connio_level_is_initial(in->level),
      none,
      connio_tx_next(io, in->level),
      in->frames,
      0 /* QUIC v1 */};
  n = tx_packet(&k, &t, wired_mspan_of(out->p, out->cap));
  if (n) {
    pnspaces_next_pn(&io->tx, in->level); /* advance only on success */
    out->len = n;
  }
  return n;
}
