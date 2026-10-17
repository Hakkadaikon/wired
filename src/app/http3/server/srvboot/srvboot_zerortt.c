#include "app/http3/server/srvboot/srvboot_impl.h"

static int  srvboot_acc_ackable(const wired_srvboot_acc* a);
static int  srvboot_zerortt_fits(const wired_srvboot_acc* a, wired_mspan dg);
static void srvboot_zerortt_buffer(wired_srvboot_acc* a, wired_mspan dg);
static usz  srvboot_acc_absorb_one(wired_srvboot_acc* a, wired_mspan pkt);
static int  srvboot_acc_feed_initial(wired_srvboot_acc* a, wired_mspan dg);

/* 1 once a has authenticated at least one Initial (something real to ack,
 * and a source address proven able to receive, RFC 9000 8.1). */
static int srvboot_acc_ackable(const wired_srvboot_acc* a) {
  return a->any && a->opened != 0;
}

usz wired_srvboot_partial_ack(
    wired_srvboot_acc* a, wired_span scid, u8* out, usz cap) {
  wired_obuf      ob = obuf_of(out, cap);
  srvwire_seal_in wi = {
      wired_span_of(a->hdr.dcid, a->hdr.dcid_len),
      wired_span_of(a->hdr.scid, a->hdr.scid_len),
      scid,
      a->ack_pn,
      (i64)a->largest_pn,
      wired_span_of(0, 0),
      0,
      a->ecn_ect0,
      a->ecn_ect1,
      a->ecn_ce,
      a->hdr.version};
  if (!srvboot_acc_ackable(a)) return 0;
  if (!srvwire_seal_initial_frames_lean(&wi, &ob)) return 0;
  a->ack_pn++;
  return ob.len;
}

int wired_srvboot_is_zerortt(const u8* dg, usz len) {
  if (!srvboot_is_initial_sized(dg, len)) return 0;
  return packet_long_type(dg[0], be_get_be32(dg + 1)) == PT_0RTT;
}

/* 1 if a has room for one more buffered 0-RTT datagram of dg's size --
 * overflow past WIRED_SRVBOOT_ZERORTT_MAX or WIRED_SRVBOOT_ZERORTT_DG_MAX is
 * silently dropped (the client's own PTO resends it over 1-RTT once 0-RTT is
 * never confirmed, RFC 9000 13.3). */
static int srvboot_zerortt_fits(const wired_srvboot_acc* a, wired_mspan dg) {
  return a->zerortt_n < WIRED_SRVBOOT_ZERORTT_MAX &&
         dg.n <= WIRED_SRVBOOT_ZERORTT_DG_MAX;
}

/* RFC 9001 4.6.1: hold dg verbatim for wired_srvboot_acc_zerortt_take once
 * this boot's 0-RTT keys exist. */
static void srvboot_zerortt_buffer(wired_srvboot_acc* a, wired_mspan dg) {
  if (!srvboot_zerortt_fits(a, dg)) return;
  for (usz i = 0; i < dg.n; i++) a->zerortt_dg[a->zerortt_n][i] = dg.p[i];
  a->zerortt_len[a->zerortt_n] = dg.n;
  a->zerortt_n++;
}

/* One coalesced packet out of an Initial datagram: an Initial is opened
 * into the accumulator; a 0-RTT packet riding behind it in the same
 * datagram (RFC 9000 12.2 -- picoquic coalesces its first 0-RTT packet
 * with the ClientHello) is held for replay exactly like a standalone
 * 0-RTT datagram (RFC 9001 4.6.1: its keys do not exist yet), instead of
 * being silently dropped -- the peer counts it as sent-but-never-acked
 * and its early data stalls. Anything else is ignored. */
static usz srvboot_acc_absorb_one(wired_srvboot_acc* a, wired_mspan pkt) {
  if (wired_srvboot_is_zerortt(pkt.p, pkt.n)) {
    srvboot_zerortt_buffer(a, pkt);
    return 0; /* buffered, but not an authenticated Initial */
  }
  return (usz)srvboot_acc_take(a, pkt);
}

/* Absorb every coalesced packet in dg into a. Split out of
 * wired_srvboot_acc_feed so its own 0-RTT/Initial dispatch stays <=3. */
static int srvboot_acc_feed_initial(wired_srvboot_acc* a, wired_mspan dg) {
  const u8* pkts[SRVBOOT_ACC_PKTS];
  usz       offs[SRVBOOT_ACC_PKTS], lens[SRVBOOT_ACC_PKTS], n, got = 0;
  pktlist   pl = {pkts, offs, lens, SRVBOOT_ACC_PKTS};
  if (!srvboot_acc_admit(a, dg)) return 0;
  n = udploop_split(wired_span_of(dg.p, dg.n), &pl);
  for (usz i = 0; i < n; i++)
    got += srvboot_acc_absorb_one(a, wired_mspan_of(dg.p + offs[i], lens[i]));
  return got != 0;
}

int wired_srvboot_acc_feed(wired_srvboot_acc* a, wired_mspan dg) {
  if (wired_srvboot_is_zerortt(dg.p, dg.n)) {
    srvboot_zerortt_buffer(a, dg);
    return 1;
  }
  return srvboot_acc_feed_initial(a, dg);
}

/* RFC 9001 4.6.1 / 5.7: hold dg verbatim -- a 0-RTT datagram before its
 * keys exist, or a 1-RTT datagram before the client Finished is verified
 * (the server MUST NOT process it yet) -- for
 * wired_srvboot_acc_zerortt_take to replay once processable. */
void wired_srvboot_acc_hold(wired_srvboot_acc* a, wired_mspan dg) {
  srvboot_zerortt_buffer(a, dg);
}

usz wired_srvboot_acc_zerortt_count(const wired_srvboot_acc* a) {
  return a->zerortt_n;
}

wired_span wired_srvboot_acc_zerortt_take(const wired_srvboot_acc* a, usz i) {
  if (i >= a->zerortt_n) return wired_span_of(0, 0);
  return wired_span_of(a->zerortt_dg[i], a->zerortt_len[i]);
}

int wired_srvboot_acc_complete(const wired_srvboot_acc* a) {
  /* RFC 8446 4.1.4: after a HelloRetryRequest the message that must be
   * whole is ClientHello2, at the crypto-stream offset right past
   * ClientHello1 (hrr_off; 0 -- the leading message -- before any HRR). */
  return a->any && crecv_complete_message_at(&a->cr, a->hrr_off);
}
