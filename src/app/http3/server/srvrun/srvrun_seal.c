#include "app/http3/server/srvrun/srvrun_impl.h"

static u64 srvrun_wt_bidi_delivered_total(const srvrun_conn* c);
static u64 srvrun_wt_uni_delivered_total(const srvrun_conn* c);
static usz srvrun_challenge_plaintext_len(usz dcid_len);
static usz srvrun_path_payload(u8* pl, u8 type, const u8* data, usz n);

/* RFC 9000 4.1/19.9: this connection's total WT receive progress across every
 * in-use bidi and uni slot -- the raw ingredient srvrun_grant_conn_credit
 * sums into one connection-wide MAX_DATA ceiling, mirroring
 * srvrun_conn_consumed_bytes' send-side fan-out shape for the opposite
 * direction. */
/* Sum of delivered_len across every in-use wt_streams (bidi) slot -- the
 * bidi half of srvrun_wt_rx_delivered_total's fan-out, split out so each
 * loop stays at the CCN gate. */
static u64 srvrun_wt_bidi_delivered_total(const srvrun_conn* c) {
  u64 total = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++) {
    if (c->l.wt_streams[i].in_use) {
      total += c->l.wt_streams[i].delivered_len;
    }
  }
  return total;
}

/* Sum of delivered_len across every in-use wt_uni_streams slot -- the uni
 * half of srvrun_wt_rx_delivered_total's fan-out. */
static u64 srvrun_wt_uni_delivered_total(const srvrun_conn* c) {
  u64 total = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++) {
    if (c->l.wt_uni_streams[i].in_use) {
      total += c->l.wt_uni_streams[i].delivered_len;
    }
  }
  return total;
}

u64 srvrun_wt_rx_delivered_total(const srvrun_conn* c) {
  return srvrun_wt_bidi_delivered_total(c) + srvrun_wt_uni_delivered_total(c);
}

/* RFC 9000 8.2.1: the plaintext length that seals to exactly the 1200-byte
 * minimum datagram for a dcid_len-byte DCID -- the short header costs
 * byte0 + DCID + a 4-byte packet number, and the AEAD tag 16 bytes (GCM
 * and Poly1305 alike). */
static usz srvrun_challenge_plaintext_len(usz dcid_len) {
  return MIN_INITIAL_DATAGRAM - (5 + dcid_len) - GCM_TAG;
}

/* n frames of type, one per 8-byte data[i], into pl; their length. */
static usz srvrun_path_payload(u8* pl, u8 type, const u8* data, usz n) {
  usz len = 0;
  for (usz i = 0; i < n; i++) {
    len += path_encode(
        pl + len, MIN_INITIAL_DATAGRAM - len, type, data + i * PATH_DATA);
  }
  return len;
}

/* Seal n PATH_CHALLENGE or PATH_RESPONSE frames (RFC 9000 19.17/19.18) as
 * one 1-RTT packet to DCID dcid, mirroring srvrun_seal_max_data. RFC 9000
 * 8.2.1 demands the datagram be expanded to 1200 bytes: the PADDING goes
 * INSIDE the AEAD, because a short header has no Length field -- bytes
 * appended after the seal join the ciphertext and the peer's tag check
 * fails (observed live: ngtcp2 discarded every challenge with a checktag
 * error, so no PATH_RESPONSE ever came back). */
int srvrun_seal_path_frames(
    srvrun_conn* c,
    wired_span   dcid,
    u8           type,
    const u8*    data,
    usz          n,
    wired_obuf*  out) {
  u8                    pl[MIN_INITIAL_DATAGRAM];
  wired_srvloop_send_in sin;
  usz                   want = srvrun_challenge_plaintext_len(dcid.n);
  usz                   pln  = srvrun_path_payload(pl, type, data, n);
  if (!pln) {
    return 0;
  }
  for (; pln < want; pln++) {
    pl[pln] = 0; /* PADDING frames (0x00) */
  }
  sin = (wired_srvloop_send_in){
      dcid, c->l.tx_pn++, -1, wired_span_of(pl, pln), 0, 0, 0, 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Seal one MAX_DATA frame (RFC 9000 19.9) as its own 1-RTT packet and send
 * it, mirroring srvrun_seal_max_stream_data for the connection-wide frame. */
int srvrun_seal_max_data(srvrun_conn* c, u64 value, wired_obuf* out) {
  u8                    pl[24];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  data_frame            f   = {value};
  wired_srvloop_send_in sin;
  usz                   pln = max_data_encode(plb.p, plb.cap, &f);
  if (!pln) {
    return 0;
  }
  plb.len = pln;
  sin     = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      c->l.tx_pn++,
      -1,
      wired_span_of(pl, pln),
      0,
      0,
      0,
      0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

void srvrun_send_max_data(const srvrun_cfg* cfg, srvrun_conn* c, u64 value) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_max_data(c, value, &ob)) {
    return;
  }
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "WT MAX_DATA sent\n");
}
