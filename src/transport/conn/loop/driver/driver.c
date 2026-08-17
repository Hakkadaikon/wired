#include "transport/conn/loop/driver/driver.h"

#include "transport/packet/frame/frame/frame.h"

/* RFC 8446 4 / RFC 9001 4: the joint handshake transcript as (msg_type, level)
 * pairs, in the single order hsdriver advances through. The client sends only
 * the first message (ClientHello) and receives the rest; the server receives
 * the first and sends the rest. Each sent or received message advances both
 * peers' order machines one step, so the two flights interleave into exactly
 * this sequence. */
static const u8 g_order[DRIVER_FLIGHT_MAX][2] = {
    {HSD_CLIENT_HELLO, HSD_PROT_INITIAL},
    {HSD_SERVER_HELLO, HSD_PROT_INITIAL},
    {HSD_ENCRYPTED_EXT, HSD_PROT_HANDSHAKE},
    {HSD_CERTIFICATE, HSD_PROT_HANDSHAKE},
    {HSD_CERT_VERIFY, HSD_PROT_HANDSHAKE},
    {HSD_FINISHED, HSD_PROT_HANDSHAKE},
    {HSD_HANDSHAKE_DONE, HSD_PROT_1RTT},
};
#define G_ORDER_LEN DRIVER_FLIGHT_MAX

void driver_init(driver* d, int is_server, wired_span dcid) {
  initial_keys   k0  = {0};
  connio_init_in cin = {is_server, 0x43, 1u << 20};
  connio_init(&d->io, dcid, &cin);
  d->io.loop.validated = 1; /* RFC 9000 8.1: test path is pre-validated */
  keyset_install(&d->io.loop.keys, LEVEL_INITIAL, &k0);
  hsdriver_init(&d->hs, is_server);
  keysched_init(&d->ks);
  d->is_server = is_server;
  d->tx_sent   = 0;
  d->rx_done   = 0;
  d->tx_off    = 0;
  d->in_len    = 0;
  d->out_len   = 0;
}

void driver_feed(driver* d, const u8* dgram, usz len) {
  usz i;
  if (len > DRIVER_DGRAM_CAP) len = DRIVER_DGRAM_CAP;
  for (i = 0; i < len; i++) d->in_buf[i] = dgram[i];
  d->in_len = len;
}

usz driver_take(driver* d, u8* out, usz cap) {
  usz i, n = d->out_len;
  if (n > cap) n = cap;
  for (i = 0; i < n; i++) out[i] = d->out_buf[i];
  d->out_len = 0;
  return n;
}

/* The transcript index this peer reaches next. Both tx and rx walk the one
 * shared order, so the position is sent + received messages. */
static u8 hs_pos(const driver* d) { return (u8)(d->tx_sent + d->rx_done); }

/* This peer sends transcript index `pos`: the client sends only index 0, the
 * server sends every index except 0. */
static int sends_index(const driver* d, u8 pos) {
  return d->is_server ? (pos != 0) : (pos == 0);
}

/* connio uses one key per level for both seal and open, so both peers install
 * the same direction's material to interoperate (RFC 9001 5). */
static void install_level(driver* d, int level, int which) {
  const initial_keys* k;
  if (keysched_get(&d->ks, which, &k))
    keyset_install(&d->io.loop.keys, level, k);
}

/* RFC 8446 7.1: derive and install the keys a handled message unlocks.
 * ServerHello unlocks Handshake keys, Finished unlocks 1-RTT. Idempotent:
 * keyschedule rejects an out-of-stage advance, so a repeat is a no-op. */
static void derive_for(driver* d, u8 msg_type) {
  static const u8 ecdhe[32] = {0};
  static const u8 tr[1]     = {0};
  if (msg_type == HSD_SERVER_HELLO) {
    keysched_advance_handshake(
        &d->ks, wired_span_of(ecdhe, sizeof(ecdhe)), wired_span_of(tr, 1));
    install_level(d, LEVEL_HANDSHAKE, KS_CLIENT_HS);
  } else if (msg_type == HSD_FINISHED) {
    keysched_advance_master(&d->ks, tr, 1);
    install_level(d, LEVEL_ONERTT, KS_CLIENT_AP);
  }
}

/* RFC 8446 4.4: CertificateVerify marks the peer authenticated, opening the
 * gate hsdriver enforces before the Finished step. */
static void advance_order(driver* d, u8 msg_type, u8 level) {
  if (msg_type == HSD_CERT_VERIFY) hsdriver_cert_verified(&d->hs);
  hsdriver_recv(&d->hs, msg_type, level);
}

/* RFC 9001 4.9: the connloop send-level ceiling tracks handshake completion;
 * mirror the order machine's verdict so 1-RTT may be sent once complete. */
static void sync_completion(driver* d) {
  d->io.loop.handshake_complete  = hsdriver_complete(&d->hs);
  d->io.loop.handshake_confirmed = hsdriver_confirmed(&d->hs);
}

/* A queued datagram is waiting and the next transcript step is one this peer
 * receives. */
static int can_recv(const driver* d) {
  u8 pos = hs_pos(d);
  return d->in_len != 0 && pos < G_ORDER_LEN && !sends_index(d, pos);
}

/* Open the queued datagram through connio (real AEAD + frame dispatch) at the
 * given level and recover the one carried message byte into *msg. Returns 1 if
 * a single byte was recovered, 0 if the open was gated/failed. Clears the
 * inbox either way. */
static int open_message(driver* d, u8 level, u8* msg) {
  u8         got[DRIVER_DGRAM_CAP];
  wired_obuf gb = obuf_of(got, sizeof(got));
  int ok    = connio_recv(&d->io, level, wired_mspan_of(d->in_buf, d->in_len));
  d->in_len = 0;
  if (!ok) return 0;
  stream_read_pull(&d->io.stream, &gb);
  *msg = got[0];
  return gb.len == 1;
}

/* Process the queued datagram: open it, advance the order machine and key
 * schedule with the recovered message. Returns 1 if a message was processed. */
static int do_recv(driver* d) {
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
static int can_send(const driver* d) {
  u8 pos = hs_pos(d);
  return d->out_len == 0 && pos < G_ORDER_LEN && sends_index(d, pos);
}

/* Seal the next outbound transcript message: a one-byte STREAM frame carrying
 * the message type, at its protection level, through connio. */
static int do_send(driver* d) {
  u8           pos = hs_pos(d), msg, level, frames[32];
  stream_frame stf;
  usz          fl, n;
  if (!can_send(d)) return 0;
  msg   = g_order[pos][0];
  level = g_order[pos][1];
  derive_for(d, msg); /* keys for this send level (server SH/Finished/Done) */
  stf.stream_id = 0;
  stf.offset    = d->tx_off;
  stf.length    = 1;
  stf.data      = &msg;
  stf.fin       = 0;
  fl            = frame_put_stream(frames, sizeof(frames), &stf);
  {
    connio_send_in sin = {level, wired_span_of(frames, fl)};
    wired_obuf     ob  = obuf_of(d->out_buf, sizeof(d->out_buf));
    n                  = connio_send(&d->io, &sin, &ob);
  }
  if (n == 0) return 0;
  advance_order(d, msg, level);
  d->out_len = n;
  d->tx_off++;
  d->tx_sent++;
  return 1;
}

int driver_step(driver* d) {
  int adv = do_recv(d);
  sync_completion(d);
  if (adv) return 1;
  adv = do_send(d);
  sync_completion(d);
  return adv;
}

int driver_handshake_complete(const driver* d) {
  return hsdriver_complete(&d->hs);
}

/* Keep running while steps remain and the handshake is not yet complete. */
static int driver_run_continues(driver* d, usz i, usz max_steps) {
  return i < max_steps && !driver_handshake_complete(d);
}

usz driver_run(driver* d, usz max_steps) {
  usz i = 0;
  while (driver_run_continues(d, i, max_steps) && driver_step(d)) i++;
  return i;
}
