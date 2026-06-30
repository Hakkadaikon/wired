#include "transport/conn/loop/connrunner/recv.h"

#include "crypto/kdf/keys/keyset.h"
#include "transport/conn/loop/connrunner/keyupdate.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/conn/loop/connrunner/reconnect.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/recovery/rtx/sentmeta/on_ack.h"

#define QUIC_CONNRUNNER_MAXPKTS 8 /* coalesced packets per datagram */

/* RFC 9001 6.3: for a 1-RTT short-header packet, drive the read-key generation
 * off its Key Phase bit; -1 means the generation it names has no key, so the
 * packet is dropped. Long-header levels are not key-phase gated. */
static int phase_admits(quic_connrunner *r, u8 byte0, int level) {
  if (level != QUIC_LEVEL_ONERTT) return 1;
  return quic_connrunner_recv_keygen(r, byte0) != -1;
}

/* Classify pkt at *level and confirm a key-phase-admitted 1-RTT packet (RFC
 * 9001 6.3); the compound lives here so recv_one carries one guard. */
static int recv_level(quic_connrunner *r, u8 byte0, int *level) {
  return quic_connrunner_packet_level(byte0, level) &&
         phase_admits(r, byte0, *level);
}

/* RFC 9001 5: open one packet slice at `level` and read back whether it
 * elicited an ACK. The dispatch state's ack_eliciting flag is cleared first so
 * it reflects only this packet. Returns 1 if accepted. */
static int open_one(
    quic_connrunner *r, int level, u8 *pkt, usz len, int *elicited) {
  r->io.disp.ack_eliciting = 0;
  r->io.disp.has_ack       = 0;
  if (!quic_connio_recv(&r->io, level, pkt, len)) return 0;
  *elicited = r->io.disp.ack_eliciting; /* RFC 9000 13.2.1 */
  return 1;
}

/* RFC 9000 17.2.5/6.2 then RFC 9001 5: drive a Retry/VN reconnect off the
 * receive path; otherwise classify and open the protected packet. A Retry/VN
 * is handled but never queued as an ack-eliciting receive (returns 0). */
static int recv_one(quic_connrunner *r, u8 *pkt, usz len, int *elicited) {
  int level;
  if (quic_connrunner_recv_reconnect(r, pkt, len)) return 0;
  if (!recv_level(r, pkt[0], &level)) return 0;
  return open_one(r, level, pkt, len, elicited);
}

/* Feed an accepted packet's ACK obligation into the loop (RFC 9000 13.2.1). */
static void feed_loop(quic_connrunner *r, int elicited) {
  quic_evloop_on_receive(&r->loop, elicited);
}

usz quic_connrunner_process_datagram(quic_connrunner *r, u8 *dgram, usz len) {
  const u8 *pkts[QUIC_CONNRUNNER_MAXPKTS];
  usz       offs[QUIC_CONNRUNNER_MAXPKTS], lens[QUIC_CONNRUNNER_MAXPKTS], n, i;
  usz       accepted = 0;
  n = quic_udploop_split(dgram, len, pkts, offs, lens, QUIC_CONNRUNNER_MAXPKTS);
  for (i = 0; i < n; i++) {
    int elicited = 0;
    if (!recv_one(r, dgram + offs[i], lens[i], &elicited)) continue;
    feed_loop(r, elicited);
    accepted++;
  }
  return accepted;
}

/* RFC 9002 A.2.2: a tracked slot at or below the Largest Acknowledged. */
static int slot_acked(const quic_sentmeta_pkt *p, u64 largest) {
  return p->used && p->pn <= largest;
}

/* Acknowledge slot i if it is at or below `largest`. */
static void ack_one(quic_sentmeta *m, usz i, u64 largest) {
  u64 t;
  int e;
  if (slot_acked(&m->pkts[i], largest))
    quic_sentmeta_on_ack(m, m->pkts[i].pn, &t, &e);
}

void quic_connrunner_track_acks(quic_connrunner *r) {
  if (!r->io.disp.has_ack) return;
  for (usz i = 0; i < QUIC_SENTMETA_CAP; i++)
    ack_one(&r->sent, i, r->io.disp.largest_acked);
}
