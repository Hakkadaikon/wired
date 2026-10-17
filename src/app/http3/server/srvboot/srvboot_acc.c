#include "app/http3/server/srvboot/srvboot_impl.h"

static u8  srvboot_cid_diff(const u8* x, const u8* y, u8 len);
static int srvboot_cid_match(const u8* x, u8 len, const u8* y, u8 ylen);
static int srvboot_acc_alt_match(
    const wired_srvboot_acc* a, const wired_header* h);
static int srvboot_acc_same_dcid(const wired_srvboot_acc* a, wired_mspan dg);
static int srvboot_acc_bind(wired_srvboot_acc* a, wired_mspan dg);
static int srvboot_pkt_initial_version(wired_mspan pkt, u32* v);
static int srvboot_cid_len_ok(usz n);

void wired_srvboot_acc_reset(wired_srvboot_acc* a) {
  crecv_init(&a->cr);
  a->largest_pn = 0;
  a->any        = 0;
  a->opened     = 0;
  /* the accept flight's server Initial is pn 1 (srvboot_flight); partial
   * acks climb from 2 so the peer never mistakes the flight for a dup */
  a->ack_pn       = 2;
  a->hrr_off      = 0;
  a->ini_tx_off   = 0;
  a->ecn_ect0     = 0;
  a->ecn_ect1     = 0;
  a->ecn_ce       = 0;
  a->alt_dcid_len = 0;
  a->zerortt_n    = 0;
}

/* RFC 9000 13.4.1: one received datagram's ECN codepoint advances the
 * matching cumulative counter (same table dispatch as srvloop's own
 * wired_srvloop_ecn_note; 0 = Not-ECT counts nothing). */
void wired_srvboot_acc_ecn_note(wired_srvboot_acc* a, u8 ecn) {
  u64* table[4] = {0, &a->ecn_ect1, &a->ecn_ect0, &a->ecn_ce};
  u64* counter  = ecn < 4 ? table[ecn] : (u64*)0;
  if (counter) {
    (*counter)++;
  }
}

/* Accumulated byte difference between two ids of the same length. */
static u8 srvboot_cid_diff(const u8* x, const u8* y, u8 len) {
  u8 diff = 0;
  for (u8 i = 0; i < len; i++) {
    diff |= x[i] ^ y[i];
  }
  return diff;
}

/* 1 if the len-byte id x equals the ylen-byte id y. */
static int srvboot_cid_match(const u8* x, u8 len, const u8* y, u8 ylen) {
  if (len != ylen) {
    return 0;
  }
  return srvboot_cid_diff(x, y, len) == 0;
}

/* 1 if h's DCID equals the allowed alternate; never matches while none is
 * allowed (a zero-length DCID must not alias the unset state). */
static int srvboot_acc_alt_match(
    const wired_srvboot_acc* a, const wired_header* h) {
  return a->alt_dcid_len != 0 &&
         srvboot_cid_match(h->dcid, h->dcid_len, a->alt_dcid, a->alt_dcid_len);
}

/* 1 if dg's DCID equals the accumulator's bound one (its Initial keys) or
 * the allowed alternate (the server's own scid the client switched to,
 * wired_srvboot_acc_allow). */
static int srvboot_acc_same_dcid(const wired_srvboot_acc* a, wired_mspan dg) {
  wired_header h;
  if (!wired_header_parse(dg.p, dg.n, &h)) {
    return 0;
  }
  return srvboot_cid_match(h.dcid, h.dcid_len, a->hdr.dcid, a->hdr.dcid_len) ||
         srvboot_acc_alt_match(a, &h);
}

/* Bind the accumulator to its first datagram's header. */
static int srvboot_acc_bind(wired_srvboot_acc* a, wired_mspan dg) {
  if (!wired_header_parse(dg.p, dg.n, &a->hdr)) {
    return 0;
  }
  a->any = 1;
  return 1;
}

/* 1 if dg may feed a: an Initial, and (after the first) the same DCID. */
int srvboot_acc_admit(wired_srvboot_acc* a, wired_mspan dg) {
  if (!wired_srvboot_is_initial(dg.p, dg.n)) {
    return 0;
  }
  if (a->any) {
    return srvboot_acc_same_dcid(a, dg);
  }
  return srvboot_acc_bind(a, dg);
}

/* The packet's own long-header Version field, if it admits pkt as an
 * Initial under that version's type bits. Reading it per packet (not from
 * the accumulator's first-datagram header) keeps a client that switched to
 * the negotiated compatible version mid-boot (RFC 9368 2.3 -- e.g. its
 * post-HelloRetryRequest second Initial) openable with the keys its own
 * Version field names. */
static int srvboot_pkt_initial_version(wired_mspan pkt, u32* v) {
  if (pkt.n < 6) {
    return 0;
  }
  *v = be_get_be32(pkt.p + 1);
  return srvboot_is_long_initial(pkt.p[0], *v);
}

/* Open one coalesced packet slice if it is an Initial and absorb its CRYPTO
 * chunks and packet number; other packet types and chunks falling outside
 * the buffer are skipped (RFC 9000 12.2 / 19.6). */
int srvboot_acc_take(wired_srvboot_acc* a, wired_mspan pkt) {
  wired_span payload;
  wired_span odcid = wired_span_of(a->hdr.dcid, a->hdr.dcid_len);
  u32        v;
  if (!srvboot_pkt_initial_version(pkt, &v)) {
    return 0;
  }
  if (!initpkt_open_ver(odcid, v, pkt, a->largest_pn, &payload)) {
    return 0;
  }
  crecv_collect(&a->cr, payload.p, payload.n);
  a->largest_pn =
      u64_max(a->largest_pn, srvboot_initial_pn(pkt, a->largest_pn));
  a->opened++;
  return 1;
}

/* 1 if n is a usable connection-id length (nonzero, within the cap). */
static int srvboot_cid_len_ok(usz n) {
  return n != 0 && n <= WIRED_MAX_CID_LEN;
}

void wired_srvboot_acc_allow(wired_srvboot_acc* a, wired_span dcid) {
  if (!srvboot_cid_len_ok(dcid.n)) {
    return;
  }
  for (usz i = 0; i < dcid.n; i++) {
    a->alt_dcid[i] = dcid.p[i];
  }
  a->alt_dcid_len = (u8)dcid.n;
}
