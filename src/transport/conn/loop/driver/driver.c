#include "transport/conn/loop/driver/driver.h"

#include "transport/packet/frame/frame/frame.h"

/* RFC 8446 4 / RFC 9001 4: the joint handshake transcript as (msg_type, level)
 * pairs, in the single order hsdriver advances through. The client sends only
 * the first message (ClientHello) and receives the rest; the server receives
 * the first and sends the rest. Each sent or received message advances both
 * peers' order machines one step, so the two flights interleave into exactly
 * this sequence. */
static const u8 g_order[QUIC_DRIVER_FLIGHT_MAX][2] = {
    {QUIC_HSD_CLIENT_HELLO, QUIC_HSD_PROT_INITIAL},
    {QUIC_HSD_SERVER_HELLO, QUIC_HSD_PROT_INITIAL},
    {QUIC_HSD_ENCRYPTED_EXT, QUIC_HSD_PROT_HANDSHAKE},
    {QUIC_HSD_CERTIFICATE, QUIC_HSD_PROT_HANDSHAKE},
    {QUIC_HSD_CERT_VERIFY, QUIC_HSD_PROT_HANDSHAKE},
    {QUIC_HSD_FINISHED, QUIC_HSD_PROT_HANDSHAKE},
    {QUIC_HSD_HANDSHAKE_DONE, QUIC_HSD_PROT_1RTT},
};
#define G_ORDER_LEN QUIC_DRIVER_FLIGHT_MAX

void quic_driver_init(quic_driver* d, int is_server, quic_span dcid) {
  quic_initial_keys   k0  = {0};
  quic_connio_init_in cin = {is_server, 0x43, 1u << 20};
  quic_connio_init(&d->io, dcid, &cin);
  d->io.loop.validated = 1; /* RFC 9000 8.1: test path is pre-validated */
  quic_keyset_install(&d->io.loop.keys, QUIC_LEVEL_INITIAL, &k0);
  quic_hsdriver_init(&d->hs, is_server);
  quic_keysched_init(&d->ks);
  d->is_server = is_server;
  d->tx_sent   = 0;
  d->rx_done   = 0;
  d->tx_off    = 0;
  d->in_len    = 0;
  d->out_len   = 0;
}

void quic_driver_feed(quic_driver* d, const u8* dgram, usz len) {
  usz i;
  if (len > QUIC_DRIVER_DGRAM_CAP) len = QUIC_DRIVER_DGRAM_CAP;
  for (i = 0; i < len; i++) d->in_buf[i] = dgram[i];
  d->in_len = len;
}

usz quic_driver_take(quic_driver* d, u8* out, usz cap) {
  usz i, n = d->out_len;
  if (n > cap) n = cap;
  for (i = 0; i < n; i++) out[i] = d->out_buf[i];
  d->out_len = 0;
  return n;
}

/* The transcript index this peer reaches next. Both tx and rx walk the one
 * shared order, so the position is sent + received messages. */
static u8 hs_pos(const quic_driver* d) { return (u8)(d->tx_sent + d->rx_done); }

/* This peer sends transcript index `pos`: the client sends only index 0, the
 * server sends every index except 0. */
static int sends_index(const quic_driver* d, u8 pos) {
  return d->is_server ? (pos != 0) : (pos == 0);
}

/* connio uses one key per level for both seal and open, so both peers install
 * the same direction's material to interoperate (RFC 9001 5). */
static void install_level(quic_driver* d, int level, int which) {
  const quic_initial_keys* k;
  if (quic_keysched_get(&d->ks, which, &k))
    quic_keyset_install(&d->io.loop.keys, level, k);
}

/* RFC 8446 7.1: derive and install the keys a handled message unlocks.
 * ServerHello unlocks Handshake keys, Finished unlocks 1-RTT. Idempotent:
 * keyschedule rejects an out-of-stage advance, so a repeat is a no-op. */
static void derive_for(quic_driver* d, u8 msg_type) {
  static const u8 ecdhe[32] = {0};
  static const u8 tr[1]     = {0};
  if (msg_type == QUIC_HSD_SERVER_HELLO) {
    quic_keysched_advance_handshake(
        &d->ks, quic_span_of(ecdhe, sizeof(ecdhe)), quic_span_of(tr, 1));
    install_level(d, QUIC_LEVEL_HANDSHAKE, QUIC_KS_CLIENT_HS);
  } else if (msg_type == QUIC_HSD_FINISHED) {
    quic_keysched_advance_master(&d->ks, tr, 1);
    install_level(d, QUIC_LEVEL_ONERTT, QUIC_KS_CLIENT_AP);
  }
}

/* RFC 8446 4.4: CertificateVerify marks the peer authenticated, opening the
 * gate hsdriver enforces before the Finished step. */
static void advance_order(quic_driver* d, u8 msg_type, u8 level) {
  if (msg_type == QUIC_HSD_CERT_VERIFY) quic_hsdriver_cert_verified(&d->hs);
  quic_hsdriver_recv(&d->hs, msg_type, level);
}

/* RFC 9001 4.9: the connloop send-level ceiling tracks handshake completion;
 * mirror the order machine's verdict so 1-RTT may be sent once complete. */
static void sync_completion(quic_driver* d) {
  d->io.loop.handshake_complete  = quic_hsdriver_complete(&d->hs);
  d->io.loop.handshake_confirmed = quic_hsdriver_confirmed(&d->hs);
}

/* A queued datagram is waiting and the next transcript step is one this peer
 * receives. */
static int can_recv(const quic_driver* d) {
  u8 pos = hs_pos(d);
  return d->in_len != 0 && pos < G_ORDER_LEN && !sends_index(d, pos);
}

/* Open the queued datagram through connio (real AEAD + frame dispatch) at the
 * given level and recover the one carried message byte into *msg. Returns 1 if
 * a single byte was recovered, 0 if the open was gated/failed. Clears the
 * inbox either way. */
static int open_message(quic_driver* d, u8 level, u8* msg) {
  u8        got[QUIC_DRIVER_DGRAM_CAP];
  quic_obuf gb = quic_obuf_of(got, sizeof(got));
  int ok = quic_connio_recv(&d->io, level, quic_mspan_of(d->in_buf, d->in_len));
  d->in_len = 0;
  if (!ok) return 0;
  quic_stream_read_pull(&d->io.stream, &gb);
  *msg = got[0];
  return gb.len == 1;
}

/* Process the queued datagram: open it, advance the order machine and key
 * schedule with the recovered message. Returns 1 if a message was processed. */
static int do_recv(quic_driver* d) {
  u8 pos = hs_pos(d), level, msg;
  if (!can_recv(d)) return 0;
  level = g_order[pos][1];
  derive_for(
      d, g_order[pos][0]); /* keys before this level opens (RFC 9001 4) */
  if (!open_message(d, level, &msg)) return 0;
  advance_order(d, msg, level); /* wire-recovered type drives the order */
  d->rx_done++;
  return 1;
}

/* The next transcript step is one this peer sends, the outbox is free, and its
 * protection level is sendable (1-RTT needs handshake-complete, which the
 * connloop send gate enforces once sync_completion mirrors it). */
static int can_send(const quic_driver* d) {
  u8 pos = hs_pos(d);
  return d->out_len == 0 && pos < G_ORDER_LEN && sends_index(d, pos);
}

/* Seal the next outbound transcript message: a one-byte STREAM frame carrying
 * the message type, at its protection level, through connio. */
static int do_send(quic_driver* d) {
  u8                pos = hs_pos(d), msg, level, frames[32];
  quic_stream_frame stf;
  usz               fl, n;
  if (!can_send(d)) return 0;
  msg   = g_order[pos][0];
  level = g_order[pos][1];
  derive_for(d, msg); /* keys for this send level (server SH/Finished/Done) */
  stf.stream_id = 0;
  stf.offset    = d->tx_off;
  stf.length    = 1;
  stf.data      = &msg;
  stf.fin       = 0;
  fl            = quic_frame_put_stream(frames, sizeof(frames), &stf);
  {
    quic_connio_send_in sin = {level, quic_span_of(frames, fl)};
    quic_obuf           ob  = quic_obuf_of(d->out_buf, sizeof(d->out_buf));
    n                       = quic_connio_send(&d->io, &sin, &ob);
  }
  if (n == 0) return 0;
  advance_order(d, msg, level);
  d->out_len = n;
  d->tx_off++;
  d->tx_sent++;
  return 1;
}

int quic_driver_step(quic_driver* d) {
  int adv = do_recv(d);
  sync_completion(d);
  if (adv) return 1;
  adv = do_send(d);
  sync_completion(d);
  return adv;
}

int quic_driver_handshake_complete(const quic_driver* d) {
  return quic_hsdriver_complete(&d->hs);
}

/* Keep running while steps remain and the handshake is not yet complete. */
static int driver_run_continues(quic_driver* d, usz i, usz max_steps) {
  return i < max_steps && !quic_driver_handshake_complete(d);
}

usz quic_driver_run(quic_driver* d, usz max_steps) {
  usz i = 0;
  while (driver_run_continues(d, i, max_steps) && quic_driver_step(d)) i++;
  return i;
}
