#include "transport/conn/loop/connrunner/recv.h"

#include "common/bytes/util/ct.h"
#include "crypto/kdf/keys/keyset.h"
#include "transport/conn/loop/connrunner/keyupdate.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/conn/loop/connrunner/reconnect.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/header/dcidresolve/dcidresolve.h"
#include "transport/recovery/rtx/sentmeta/on_ack.h"

#define QUIC_CONNRUNNER_MAXPKTS 8 /* coalesced packets per datagram */

/* RFC 9000 12.2: a coalesced packet whose Destination Connection ID differs
 * from the connection's own is ignored (not just this packet dropped as
 * malformed -- the datagram's other, matching packets still process). A
 * packet too short to carry the DCID length it claims (dcid_len < 0) is
 * rejected the same way a real mismatch would be. */
static int dcid_matches(const connrunner* r, wired_mspan pkt) {
  int        dcid_len = dcidresolve_len(pkt, r->io.dcid_len);
  wired_span dcid;
  if (dcid_len < 0 || (u8)dcid_len != r->io.dcid_len) return 0;
  dcid = dcidresolve_dcid(pkt, dcid_len);
  return ct_diffn(dcid.p, r->io.dcid, r->io.dcid_len) == 0;
}

/* RFC 9001 6.3: for a 1-RTT short-header packet, drive the read-key generation
 * off its Key Phase bit; -1 means the generation it names has no key, so the
 * packet is dropped. Long-header levels are not key-phase gated. */
static int phase_admits(connrunner* r, u8 byte0, int level) {
  if (level != QUIC_LEVEL_ONERTT) return 1;
  return connrunner_recv_keygen(r, byte0) != -1;
}

/* Classify pkt at *level and confirm a key-phase-admitted 1-RTT packet (RFC
 * 9001 6.3); the compound lives here so recv_one carries one guard. */
static int recv_level(connrunner* r, u8 byte0, int* level) {
  return connrunner_packet_level(byte0, level) &&
         phase_admits(r, byte0, *level);
}

/* RFC 9000 12.2 then 9001 6.3: a packet admitted at all only once its DCID
 * names this connection (a mismatched coalesced packet is ignored, not just
 * dropped as malformed). */
static int recv_level_and_dcid(connrunner* r, wired_mspan pkt, int* level) {
  return recv_level(r, pkt.p[0], level) && dcid_matches(r, pkt);
}

/* The protection level and packet slice open_one opens. */
typedef struct {
  int         level;
  wired_mspan pkt;
} recv_open_in;

/* RFC 9001 5: open one packet slice at `in->level` and read back whether it
 * elicited an ACK. The dispatch state's ack_eliciting flag is cleared first so
 * it reflects only this packet. Returns 1 if accepted. */
static int open_one(connrunner* r, const recv_open_in* in, int* elicited) {
  r->io.disp.ack_eliciting = 0;
  r->io.disp.has_ack       = 0;
  if (!connio_recv(&r->io, in->level, in->pkt)) return 0;
  *elicited = r->io.disp.ack_eliciting; /* RFC 9000 13.2.1 */
  return 1;
}

/* RFC 9000 17.2.5/6.2 then RFC 9001 5: drive a Retry/VN reconnect off the
 * receive path; otherwise classify and open the protected packet. A Retry/VN
 * is handled but never queued as an ack-eliciting receive (returns 0). */
static int recv_one(connrunner* r, wired_mspan pkt, int* elicited) {
  recv_open_in in = {0, pkt};
  if (connrunner_recv_reconnect(r, pkt.p, pkt.n)) return 0;
  if (!recv_level_and_dcid(r, pkt, &in.level)) return 0;
  return open_one(r, &in, elicited);
}

/* Feed an accepted packet's ACK obligation into the loop (RFC 9000 13.2.1). */
static void feed_loop(connrunner* r, int elicited) {
  evloop_on_receive(&r->loop, elicited);
}

usz connrunner_process_datagram(connrunner* r, wired_mspan dgram) {
  const u8* pkts[QUIC_CONNRUNNER_MAXPKTS];
  usz       offs[QUIC_CONNRUNNER_MAXPKTS], lens[QUIC_CONNRUNNER_MAXPKTS], n, i;
  usz       accepted = 0;
  pktlist   out      = {pkts, offs, lens, QUIC_CONNRUNNER_MAXPKTS};
  n                  = udploop_split(wired_span_of(dgram.p, dgram.n), &out);
  for (i = 0; i < n; i++) {
    int elicited = 0;
    if (!recv_one(r, wired_mspan_of(dgram.p + offs[i], lens[i]), &elicited))
      continue;
    feed_loop(r, elicited);
    accepted++;
  }
  return accepted;
}

/* RFC 9002 A.2.2: a tracked slot at or below the Largest Acknowledged. */
static int slot_acked(const sentmeta_pkt* p, u64 largest) {
  return p->used && p->pn <= largest;
}

/* Acknowledge slot i if it is at or below `largest`. */
static void ack_one(sentmeta* m, usz i, u64 largest) {
  sentmeta_acked out;
  if (slot_acked(&m->pkts[i], largest)) sentmeta_on_ack(m, m->pkts[i].pn, &out);
}

void connrunner_track_acks(connrunner* r) {
  if (!r->io.disp.has_ack) return;
  for (usz i = 0; i < QUIC_SENTMETA_CAP; i++)
    ack_one(&r->sent, i, r->io.disp.largest_acked);
}
