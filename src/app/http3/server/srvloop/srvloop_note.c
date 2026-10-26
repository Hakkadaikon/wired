#include "app/http3/server/srvloop/srvloop_impl.h"

static void app_rx_record(wired_srvloop* l, const u8* pn, usz pn_len);
static void note_app_rx_short(
    wired_srvloop* l, wired_server* s, wired_mspan pkt);
static void note_app_rx_long(wired_srvloop* l, wired_mspan pkt);

/* The largest 1-RTT packet number received so far (0 before any), the baseline
 * for recovering a truncated PN (RFC 9000 A.3). */
u64 srvloop_app_largest_pn(const wired_srvloop* l) {
  return l->app_rx_seen ? l->app_rx_hi : 0;
}

/* RFC 9000 17.2/17.3: byte0's form bit tells a short-header 1-RTT packet
 * (pn right after the DCID) apart from a long-header 0-RTT one (pn past
 * Version/DCID/SCID/Length, RFC 9000 12.3 reports 0-RTT at this same App
 * pn space/level as 1-RTT, but its header shape is still long-form). */
int srvloop_app_pkt_is_long(u8 byte0) { return (byte0 & 0x80u) != 0; }

/* RFC 9000 A.3: recover the truncated PN at pn/pn_len against the largest
 * seen so far and record it as the number to ACK / the new baseline. */
static void app_rx_record(wired_srvloop* l, const u8* pn, usz pn_len) {
  u64 prev       = srvloop_app_largest_pn(l);
  l->app_rx_pn   = pnum_decode(pn, pn_len, prev);
  l->app_rx_gap  = l->app_rx_seen && l->app_rx_pn > prev + 1;
  l->app_rx_hi   = u64_max(prev, l->app_rx_pn);
  l->app_rx_seen = 1;
}

/* RFC 9000 13.2.1 / A.3: a short-header 1-RTT packet's truncated pn sits
 * right after byte0 + the server's own DCID (iscid, the id the client
 * addressed it to); byte0's low bits give its length. */
static void note_app_rx_short(
    wired_srvloop* l, wired_server* s, wired_mspan pkt) {
  app_rx_record(l, pkt.p + 1u + s->sdrv.iscid_len, (pkt.p[0] & 0x03u) + 1u);
}

/* RFC 9000 17.2.3 / 13.2.1: a 0-RTT packet keeps the App pn space (RFC 9000
 * 12.3) but wears a long header with no Token field, exactly like Handshake
 * (recv_zerortt) -- its pn sits past Version/DCID/SCID/Length, not right
 * after byte0+DCID like a short-header 1-RTT packet. */
static void note_app_rx_long(wired_srvloop* l, wired_mspan pkt) {
  lhdr h;
  if (!lhdr_parse(wired_span_of(pkt.p, pkt.n), 0, &h)) {
    return;
  }
  app_rx_record(l, pkt.p + h.pn_off, lhdr_pn_len(pkt.p[0]));
}

void srvloop_note_app_rx(
    wired_srvloop* l, wired_server* s, const srvloop_opened* o) {
  if (o->level != LEVEL_ONERTT) {
    return;
  }
  if (srvloop_app_pkt_is_long(o->pkt.p[0])) {
    note_app_rx_long(l, o->pkt);
  } else {
    note_app_rx_short(l, s, o->pkt);
  }
}

/* The largest Handshake packet number received so far (0 before any), the
 * baseline for recovering a truncated PN (RFC 9000 A.3). */
u64 srvloop_hs_largest_pn(const wired_srvloop* l) {
  return l->hs_rx_seen ? l->hs_rx_hi : 0;
}

/* RFC 9000 13.2.1: after a Handshake packet is opened (header protection
 * removed in place), re-parse its long header for the packet-number offset and
 * record the recovered PN. The client Finished does not always arrive at PN 0
 * (curl leads with an ACK-only Handshake packet), so a fixed ACK of 0 leaves
 * the Finished unacknowledged and the client PTO-retransmits it for seconds. */
void srvloop_note_hs_rx(wired_srvloop* l, const srvloop_opened* o) {
  lhdr h;
  if (o->level != LEVEL_HANDSHAKE) {
    return;
  }
  if (!lhdr_parse(wired_span_of(o->pkt.p, o->pkt.n), 0, &h)) {
    return;
  }
  l->hs_rx_pn = pnum_decode(
      o->pkt.p + h.pn_off, lhdr_pn_len(o->pkt.p[0]), srvloop_hs_largest_pn(l));
  l->hs_rx_hi   = u64_max(srvloop_hs_largest_pn(l), l->hs_rx_pn);
  l->hs_rx_seen = 1;
}
