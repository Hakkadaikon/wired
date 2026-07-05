#include "app/http3/server/srvboot/srvboot.h"

#include "app/http3/server/srvloop/send.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/num.h"
#include "transport/conn/loop/crecv/collect.h"
#include "transport/conn/loop/crecv/message.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"
#include "transport/packet/header/packet/header.h"
#include "transport/packet/header/packet/pnum.h"
#include "transport/packet/header/packet/vneg.h"

/* RFC 9000 17.2: byte0 has the long-header bit set and Initial type bits 00. */
static int srvboot_is_long_initial(u8 byte0) {
  return (byte0 & 0x80) != 0 && (byte0 & 0x30) == 0;
}

int wired_srvboot_is_initial(const u8* dg, usz len) {
  if (len < 6 || !srvboot_is_long_initial(dg[0])) return 0;
  return len >= (usz)6 + dg[5];
}

/* Init the server and its loop. The client's DCID (this Initial's DCID) is the
 * ODCID for Initial keys (RFC 9001 5.2); the client's SCID is the DCID the
 * server writes back and the loop is seeded with (RFC 9000 17.2 / 5.1). */
static int srvboot_init(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    const wired_header*       h) {
  wired_server_init_in in = {
      id->priv, id->pub, id->cert_seed, id->chain, id->chain_count};
  wired_server_init(conn->s, &in);
  wired_server_set_limits(conn->s, id->max_data, id->max_streams_bidi);
  if (!wired_server_set_cids(
          conn->s, quic_span_of(h->dcid, h->dcid_len),
          quic_span_of(id->scid, id->scid_len)))
    return 0;
  return wired_srvloop_init(conn->l, h->scid, h->scid_len);
}

/* RFC 9000 13.2.1 / A.3: the opened Initial's packet number is cleartext once
 * header protection is off; recover it against a baseline of 0 (nothing seen
 * yet in this space). A retransmitted Initial arrives with pn > 0, and the
 * ServerHello Initial must acknowledge the number actually received or the
 * peer keeps retransmitting. */
static u64 srvboot_initial_pn(quic_mspan dg) {
  quic_lhdr h;
  if (!quic_lhdr_parse(quic_span_of(dg.p, dg.n), 1, &h)) return 0;
  return quic_pnum_decode(dg.p + h.pn_off, quic_lhdr_pn_len(dg.p[0]), 0);
}

/* The two pieces of a server flight: the ServerHello (Initial space) and the
 * Handshake-space flight (Certificate/CertificateVerify/Finished). */
typedef struct {
  quic_span sh;
  quic_span flight;
} srvboot_flight_bytes;

/* The server and its fixed identity, threaded together through flight
 * sealing (they always travel as a pair). */
typedef struct {
  wired_server*           s;
  const wired_srvboot_id* id;
  u64                     ack_pn; /**< client Initial pn the flight ACKs */
} srvboot_server;

/* RFC 9000 19.6 / 14.1: TLS bytes per Handshake flight datagram. 1100 keeps
 * each sealed packet (long header + CRYPTO framing + AEAD tag) well under a
 * 1500-byte MTU datagram. */
#define SRVBOOT_HS_CHUNK 1100

static usz srvboot_chunk_len(usz remaining) {
  return remaining < SRVBOOT_HS_CHUNK ? remaining : SRVBOOT_HS_CHUNK;
}

/* Seal the flight chunk at *off as its own Handshake packet (pn = datagram
 * index, CRYPTO offset = *off, RFC 9000 19.6) appended to out->flight,
 * recording its datagram length. Returns 1, 0 on overflow or a flight that
 * needs more than WIRED_SRVBOOT_FLIGHT_MAX datagrams. */
static int srvboot_seal_next(
    const srvboot_server* sv,
    quic_span             flight,
    usz*                  off,
    wired_srvboot_out*    out) {
  usz       n    = srvboot_chunk_len(flight.n - *off);
  quic_obuf tail = quic_obuf_of(
      out->flight->p + out->flight->len, out->flight->cap - out->flight->len);
  wired_srvloop_send_in in = {
      quic_span_of(sv->id->scid, sv->id->scid_len), out->dgram_count, -1,
      quic_span_of(flight.p + *off, n), *off};
  if (out->dgram_count >= WIRED_SRVBOOT_FLIGHT_MAX) return 0;
  if (!wired_srvloop_send_handshake(sv->s, &in, &tail)) return 0;
  out->dgram_len[out->dgram_count++] = tail.len;
  out->flight->len += tail.len;
  *off += n;
  return 1;
}

/* RFC 9000 19.6: split the flight into <= SRVBOOT_HS_CHUNK-byte CRYPTO chunks,
 * one Handshake packet datagram each, concatenated into out->flight. */
static int srvboot_seal_hs_flight(
    const srvboot_server* sv, quic_span flight, wired_srvboot_out* out) {
  usz off          = 0;
  out->dgram_count = 0;
  out->flight->len = 0;
  while (off < flight.n)
    if (!srvboot_seal_next(sv, flight, &off, out)) return 0;
  return 1;
}

/* Seal the ServerHello into a server Initial datagram and the flight into
 * Handshake packet datagram(s). Separate from the Initial: it alone is padded
 * to 1200 bytes (RFC 9000 14.1), so coalescing the flight behind it would
 * exceed a 1500-byte MTU datagram. Returns 1, 0 on overflow. */
static int srvboot_seal_flight(
    const srvboot_server*       sv,
    const srvboot_flight_bytes* fb,
    wired_srvboot_out*          out) {
  wired_srvloop_send_in in0 = {
      quic_span_of(sv->id->scid, sv->id->scid_len), 1, (i64)sv->ack_pn, fb->sh,
      0};
  if (!wired_srvloop_send_initial(sv->s, &in0, out->initial)) return 0;
  return srvboot_seal_hs_flight(sv, fb->flight, out);
}

/* Build the server flight from the folded ClientHello and seal it. */
static int srvboot_flight(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    u64                       ack_pn,
    wired_srvboot_out*        out) {
  u8                   sh[512], flight[4096];
  quic_obuf            sh_ob = quic_obuf_of(sh, sizeof sh);
  quic_obuf            fl_ob = quic_obuf_of(flight, sizeof flight);
  quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
  srvboot_flight_bytes fb;
  srvboot_server       sv = {conn->s, id, ack_pn};
  if (!wired_server_build_flight(conn->s, id->random, &fo)) return 0;
  fb = (srvboot_flight_bytes){
      quic_span_of(sh, sh_ob.len), quic_span_of(flight, fl_ob.len)};
  if (!srvboot_seal_flight(&sv, &fb, out)) return 0;
  /* RFC 9000 12.3: later Handshake sends continue after the flight's packet
   * numbers 0..dgram_count-1. */
  conn->l->hs_tx_pn = out->dgram_count;
  return 1;
}

void wired_srvboot_acc_reset(wired_srvboot_acc* a) {
  quic_crecv_init(&a->cr);
  a->largest_pn = 0;
  a->any        = 0;
  a->opened     = 0;
}

/* Accumulated byte difference between two ids of the same length. */
static u8 srvboot_cid_diff(const u8* x, const u8* y, u8 len) {
  u8 diff = 0;
  for (u8 i = 0; i < len; i++) diff |= x[i] ^ y[i];
  return diff;
}

/* 1 if dg's DCID equals the accumulator's bound one (its Initial keys). */
static int srvboot_acc_same_dcid(const wired_srvboot_acc* a, quic_mspan dg) {
  wired_header h;
  if (!wired_header_parse(dg.p, dg.n, &h)) return 0;
  if (h.dcid_len != a->hdr.dcid_len) return 0;
  return srvboot_cid_diff(h.dcid, a->hdr.dcid, h.dcid_len) == 0;
}

/* Bind the accumulator to its first datagram's header. */
static int srvboot_acc_bind(wired_srvboot_acc* a, quic_mspan dg) {
  if (!wired_header_parse(dg.p, dg.n, &a->hdr)) return 0;
  a->any = 1;
  return 1;
}

/* 1 if dg may feed a: an Initial, and (after the first) the same DCID. */
static int srvboot_acc_admit(wired_srvboot_acc* a, quic_mspan dg) {
  if (!wired_srvboot_is_initial(dg.p, dg.n)) return 0;
  if (a->any) return srvboot_acc_same_dcid(a, dg);
  return srvboot_acc_bind(a, dg);
}

/* Open one coalesced packet slice if it is an Initial and absorb its CRYPTO
 * chunks and packet number; other packet types and chunks falling outside
 * the buffer are skipped (RFC 9000 12.2 / 19.6). */
static int srvboot_acc_take(wired_srvboot_acc* a, quic_mspan pkt) {
  quic_span payload;
  quic_span odcid = quic_span_of(a->hdr.dcid, a->hdr.dcid_len);
  if (!srvboot_is_long_initial(pkt.p[0])) return 0;
  if (!quic_initpkt_open(odcid, pkt, &payload)) return 0;
  quic_crecv_collect(&a->cr, payload.p, payload.n);
  a->largest_pn = quic_u64_max(a->largest_pn, srvboot_initial_pn(pkt));
  a->opened++;
  return 1;
}

/* Coalesced packets per boot datagram (RFC 9000 12.2). */
#define SRVBOOT_ACC_PKTS 4

int wired_srvboot_acc_feed(wired_srvboot_acc* a, quic_mspan dg) {
  const u8*    pkts[SRVBOOT_ACC_PKTS];
  usz          offs[SRVBOOT_ACC_PKTS], lens[SRVBOOT_ACC_PKTS], n, got = 0;
  quic_pktlist pl = {pkts, offs, lens, SRVBOOT_ACC_PKTS};
  if (!srvboot_acc_admit(a, dg)) return 0;
  n = quic_udploop_split(quic_span_of(dg.p, dg.n), &pl);
  for (usz i = 0; i < n; i++)
    got += (usz)srvboot_acc_take(a, quic_mspan_of(dg.p + offs[i], lens[i]));
  return got != 0;
}

int wired_srvboot_acc_complete(const wired_srvboot_acc* a) {
  return a->any && quic_crecv_complete_message(&a->cr);
}

/* Init the server/loop from the bound header and fold the reassembled
 * ClientHello. */
static int srvboot_acc_start(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_srvboot_acc*        a) {
  quic_span ch;
  quic_crecv_message(&a->cr, &ch.p, &ch.n);
  if (!srvboot_init(conn, id, &a->hdr)) return 0;
  return wired_server_recv_initial(conn->s, ch.p, ch.n);
}

int wired_srvboot_accept_acc(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_srvboot_acc*        a,
    wired_srvboot_out*        out) {
  if (!wired_srvboot_acc_complete(a)) return 0;
  if (!srvboot_acc_start(conn, id, a)) return 0;
  out->client_pn = a->largest_pn;
  return srvboot_flight(conn, id, a->largest_pn, out);
}

int wired_srvboot_accept(
    const wired_srvboot_conn* conn,
    const wired_srvboot_in*   in,
    wired_srvboot_out*        out) {
  wired_srvboot_acc a; /* single-datagram fast path, caller-stack lifetime */
  wired_srvboot_acc_reset(&a);
  if (!wired_srvboot_acc_feed(&a, in->dgram)) return 0;
  return wired_srvboot_accept_acc(conn, in->id, &a, out);
}

/* 1 if dg is big enough to owe a response and wears a long header
 * (RFC 9000 6: no Version Negotiation for a sub-1200-byte datagram). */
static int srvboot_vn_sized(quic_span dg) {
  return dg.n >= 1200 && (dg.p[0] & 0x80) != 0;
}

/* 1 if v is neither a Version Negotiation packet's 0 (RFC 9000 6.1) nor the
 * one version this server speaks. */
static int srvboot_vn_alien(u32 v) { return v != 0 && v != 1; }

/* 1 if dg is a long-header datagram of an unsupported version. */
static int srvboot_vn_owed(quic_span dg) {
  return srvboot_vn_sized(dg) && srvboot_vn_alien(quic_get_be32(dg.p + 1));
}

usz wired_srvboot_vneg(quic_span dg, u8* out, usz cap) {
  static const u32 versions[1] = {1};
  wired_header     h;
  quic_vneg_desc   d;
  if (!srvboot_vn_owed(dg)) return 0;
  if (!wired_header_parse(dg.p, dg.n, &h)) return 0;
  d = (quic_vneg_desc){
      quic_span_of(h.dcid, h.dcid_len), quic_span_of(h.scid, h.scid_len),
      versions, 1};
  return quic_vneg_respond(out, cap, &d);
}
