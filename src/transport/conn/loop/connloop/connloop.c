#include "transport/conn/loop/connloop/connloop.h"

#include "crypto/kdf/keys/promote.h"
#include "transport/io/udp/udploop/antiamp_gate.h"
#include "transport/recovery/rtx/sentpkt/ack_process.h"

/* Send level starts one below Initial so the first send must promote in. */
#define QUIC_CONNLOOP_NO_LEVEL (-1)

void quic_connloop_init(quic_connloop* c, int is_server) {
  quic_keyset_init(&c->keys);
  quic_sentpkt_init(&c->sent);
  c->send_level          = QUIC_CONNLOOP_NO_LEVEL;
  c->handshake_complete  = 0;
  c->handshake_confirmed = 0;
  c->validated           = 0;
  c->is_server           = is_server;
  c->phase               = QUIC_CONNLOOP_ACTIVE;
  c->pto_armed           = 0;
  c->recv_bytes          = 0;
  c->sent_bytes          = 0;
}

/* RFC 9001 4: the level's key is installed (not discarded). */
static int level_usable(const quic_connloop* c, int level) {
  const quic_initial_keys* out;
  return quic_keyset_for_level(&c->keys, level, &out);
}

/* RFC 9000 10.2: only an active connection processes incoming packets. */
static int recv_allowed(const quic_connloop* c, int level) {
  return c->phase != QUIC_CONNLOOP_CLOSED && level_usable(c, level);
}

int quic_connloop_on_recv(quic_connloop* c, int level, usz len) {
  if (c->phase == QUIC_CONNLOOP_CLOSED) return 0;
  c->recv_bytes += len; /* RFC 9000 8.1: budget grows even when dropped */
  return recv_allowed(c, level) ? 1 : 0;
}

/* RFC 9001 4.9: the level is a non-regressing, currently-permitted ceiling.
 * 1-RTT (rank 2) is barred until the handshake completes. */
static int send_level_ok(const quic_connloop* c, int level) {
  if (level <= c->send_level) return level == c->send_level;
  if (!quic_key_promote_ok(c->send_level, level)) return 0;
  return level <=
         quic_key_send_level(c->handshake_complete, c->handshake_confirmed);
}

/* RFC 9000 10.2 / 8.1: open phase, key present, and within the amp budget. */
static int send_gated(const quic_connloop* c, int level, usz len) {
  if (c->phase != QUIC_CONNLOOP_ACTIVE) return 0;
  if (!level_usable(c, level)) return 0;
  quic_pathbudget b = {c->recv_bytes, c->sent_bytes, c->validated};
  return quic_udploop_send_allowed(&b, len);
}

/* RFC 9002 6.2: arm the PTO only while ack-eliciting data is in flight. */
static void pto_sync(quic_connloop* c) {
  c->pto_armed = quic_sentpkt_count(&c->sent) > 0 ? 1 : 0;
}

/* RFC 9001 4.9 / RFC 9000 8.1: every gate a send must clear. */
static int send_ok(const quic_connloop* c, int level, usz len) {
  return send_level_ok(c, level) && send_gated(c, level, len);
}

int quic_connloop_on_send(quic_connloop* c, const quic_connloop_send_in* in) {
  if (!send_ok(c, in->level, in->len)) return 0;
  c->send_level = in->level;
  c->sent_bytes += in->len;
  if (!in->ack_eliciting) return 1;
  {
    quic_sentpkt_out pkt = {in->pn, 0, 1, in->len};
    quic_sentpkt_on_send(&c->sent, &pkt);
  }
  pto_sync(c);
  return 1;
}

void quic_connloop_validate(quic_connloop* c) {
  c->validated = 1; /* RFC 9000 8.1: anti-amplification limit lifted */
}

usz quic_connloop_on_ack(quic_connloop* c, const quic_connloop_ack_in* in) {
  u64         acked[QUIC_SENTPKT_CAP];
  usz         n      = 0;
  quic_ackset ackset = {in->ack_largest, in->ack_ranges, in->n_ranges};
  quic_ack_process(&c->sent, &ackset, (quic_u64out){acked, &n});
  pto_sync(c); /* an ACK that empties in-flight disarms the PTO */
  return n;
}

int quic_connloop_on_pto(quic_connloop* c, const quic_connloop_pto_in* in) {
  if (!level_usable(c, in->level))
    return 0; /* never probe at a discarded level */
  if (quic_sentpkt_count(&c->sent) == 0) return 0; /* no probe, stay disarmed */
  {
    quic_sentpkt_out pkt = {in->pn, 0, 1, in->len}; /* probe is a new packet */
    quic_sentpkt_on_send(&c->sent, &pkt);
  }
  c->sent_bytes += in->len;
  c->pto_armed = 1;
  return 1;
}

/* RFC 9000 10.2: the next phase per current phase. active goes to closing on a
 * local close (overridden below for a peer close); the rest march one step
 * toward closed and closed never reopens. Indexed by QUIC_CONNLOOP_*. */
static const int quic_connloop_next[] = {
    [QUIC_CONNLOOP_ACTIVE]   = QUIC_CONNLOOP_CLOSING,
    [QUIC_CONNLOOP_CLOSING]  = QUIC_CONNLOOP_DRAINING,
    [QUIC_CONNLOOP_DRAINING] = QUIC_CONNLOOP_CLOSED,
    [QUIC_CONNLOOP_CLOSED]   = QUIC_CONNLOOP_CLOSED,
};

void quic_connloop_close(quic_connloop* c, int peer_closed) {
  if (c->phase == QUIC_CONNLOOP_ACTIVE && peer_closed)
    c->phase = QUIC_CONNLOOP_DRAINING; /* peer close skips local closing */
  else
    c->phase = quic_connloop_next[c->phase];
}
