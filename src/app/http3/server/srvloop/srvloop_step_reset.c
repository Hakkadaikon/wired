#include "app/http3/server/srvloop/srvloop_impl.h"

static void srvloop_step_reset(wired_srvloop* l);
static void srvloop_step_packets(
    const wired_srvloop_conn* conn, wired_mspan dgram);

/* Clear the per-step outputs a step reports. */
static void srvloop_step_reset(wired_srvloop* l) {
  l->ack_n              = 0;
  l->ecn_ack_seen       = 0;
  l->step_np_new        = 0;
  l->ncid_rx_n          = 0;
  l->done_n             = 0;
  l->incomplete_n       = 0;
  l->frame_unexpected_n = 0;
  l->reset_slots        = 0;
  l->malformed_slots    = 0;
  l->reset_slotless_n   = 0;
}

/* Split dgram into its coalesced packets and process each one. */
static void srvloop_step_packets(
    const wired_srvloop_conn* conn, wired_mspan dgram) {
  const u8* pkts[WIRED_SRVLOOP_MAXPKTS];
  usz       offs[WIRED_SRVLOOP_MAXPKTS], lens[WIRED_SRVLOOP_MAXPKTS], n, i;
  pktlist   plist = {pkts, offs, lens, WIRED_SRVLOOP_MAXPKTS};
  n               = udploop_split(wired_span_of(dgram.p, dgram.n), &plist);
  for (i = 0; i < n; i++)
    srvloop_step_one(conn, wired_mspan_of(dgram.p + offs[i], lens[i]));
}

/* RFC 9000 12.2: a received datagram may coalesce several QUIC packets (e.g. an
 * Initial/ACK ahead of the Handshake carrying the client Finished). Split it
 * and process every slice before building one reply for the whole datagram. */
int wired_srvloop_step(
    const wired_srvloop_conn* conn, wired_mspan dgram, wired_obuf* out) {
  int answer;
  int r;
  srvloop_step_reset(conn->l);
  srvloop_step_packets(conn, dgram);
  conn->l->got_request = conn->l->done_n > 0;
  /* takeover: the caller answers the request, the loop only confirms/ACKs */
  answer = conn->l->got_request && !conn->l->resp_external;
  r      = wired_srvloop_produce(conn, answer, out);
  srvloop_rearm_reqacc(conn->l);
  srvloop_rearm_incomplete(conn->l);
  srvloop_rearm_frame_unexpected(conn->l);
  return r;
}
