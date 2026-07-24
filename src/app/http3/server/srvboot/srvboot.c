#include "app/http3/server/srvboot/srvboot.h"

#include "app/http3/server/srvloop/send.h"
#include "app/http3/server/srvwire/wire.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/num.h"
#include "transport/conn/loop/crecv/collect.h"
#include "transport/conn/loop/crecv/message.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"
#include "transport/packet/header/packet/header.h"
#include "transport/packet/header/packet/pnum.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/packet/header/packet/vneg.h"
#include "transport/version/version/compat.h"
#include "transport/version/versmgr/avail.h"

/* RFC 9000 17.2 (v1) / RFC 9369 3.2 (v2): byte0 wears a long-header Initial
 * under `version`. The type-bit layout is version-dependent (v2's Initial
 * bits are a rotation of v1's), so this always needs the packet's own
 * Version field alongside byte0, never byte0 alone. */
static int srvboot_is_long_initial(u8 byte0, u32 version) {
  return quic_packet_long_type(byte0, version) == QUIC_PT_INITIAL;
}

/* 1 if dg has room for a long header prefix (byte0 + 4-byte version) and
 * wears the long-header form bit. */
static int srvboot_is_initial_sized(const u8* dg, usz len) {
  return len >= 6 && (dg[0] & 0x80) != 0;
}

int wired_srvboot_is_initial(const u8* dg, usz len) {
  if (!srvboot_is_initial_sized(dg, len)) return 0;
  if (!srvboot_is_long_initial(dg[0], quic_get_be32(dg + 1))) return 0;
  return len >= (usz)6 + dg[5];
}

/* Init the server and its loop. The client's DCID (this Initial's DCID) is the
 * ODCID for Initial keys (RFC 9001 5.2); the client's SCID is the DCID the
 * server writes back and the loop is seeded with (RFC 9000 17.2 / 5.1). */
/* After a Retry, wire the token-recovered true ODCID (advertised as
 * original_destination_connection_id) alongside this Initial's own header
 * DCID (the key-derivation input, and the Retry's SCID advertised back as
 * retry_source_connection_id) -- three distinct RFC 9000 7.3 values that
 * must not collapse into one field (RFC 9001 5.2: reusing the true ODCID
 * for key derivation here breaks decryption of every post-Retry Initial,
 * whose keys are derived from the RETRY's SCID, not the original DCID). */
static int srvboot_set_cids(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    const wired_header*       h) {
  quic_span scid = quic_span_of(id->scid, id->scid_len);
  quic_span dcid = quic_span_of(h->dcid, h->dcid_len);
  if (!id->retry_odcid_len) return wired_server_set_cids(conn->s, dcid, scid);
  if (!quic_sdrv_set_cids_retried(
          &conn->s->sdrv, dcid, scid,
          quic_span_of(id->retry_odcid, id->retry_odcid_len)))
    return 0;
  return quic_sdrv_set_retry_scid(&conn->s->sdrv, dcid);
}

static int srvboot_init(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    const wired_header*       h) {
  wired_server_init_in in = {id->priv,     id->pub,         id->cert_seed,
                             id->chain,    id->chain_count, id->san_ipv4,
                             id->now_secs, id->ticket_key};
  wired_server_init(conn->s, &in);
  wired_server_set_limits(
      conn->s, id->max_data, id->max_streams_bidi, id->max_datagram_frame_size);
  if (!srvboot_set_cids(conn, id, h)) return 0;
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
 * sealing (they always travel as a pair). cli_scid is the client's SCID from
 * its Initial: the DCID every reply is addressed to (RFC 9000 7.2), possibly
 * zero-length (Chrome). */
typedef struct {
  wired_server*           s;
  const wired_srvboot_id* id;
  u64                     ack_pn;   /**< client Initial pn the flight ACKs */
  quic_span               cli_scid; /**< reply DCID (RFC 9000 7.2) */
  u32 version; /**< the accepted Initial's own version (RFC 9368 2: the
                * server replies in the version the client used, no VN
                * round trip) */
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
      sv->cli_scid, out->dgram_count, -1, quic_span_of(flight.p + *off, n),
      *off};
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
  wired_srvloop_send_in in0 = {sv->cli_scid, 1, (i64)sv->ack_pn, fb->sh, 0};
  if (!wired_srvloop_send_initial_ver(sv->version, sv->s, &in0, out->initial))
    return 0;
  return srvboot_seal_hs_flight(sv, fb->flight, out);
}

/* Build the server flight from the folded ClientHello and seal it, replying
 * in `version` -- the accepted Initial's own version (RFC 9368 2 / property
 * 2: this server never switches away from the version the client's first
 * flight used, so the reply is trivially compatible with it, verified
 * defensively via quic_version_compatible rather than assumed). */
/* flight sized past a real 9-cert amplificationlimit chain's Handshake
 * flight (EncryptedExtensions + 9 CERTIFICATE entries + CertificateVerify +
 * Finished) with headroom -- matches srvrun_conn.boot_hs, the buffer this
 * flight is copied into for retransmission. See
 * QUIC_TLS_CERT_CHAIN_MAX/WIRED_CERTRELOAD_CHAIN_MAX. */
#define SRVBOOT_SH_MAX 512
#define SRVBOOT_HS_FLIGHT_MAX 16384

/* Build the TLS server flight (ServerHello + Handshake messages) into fb's
 * backing buffers, replying in `version` -- gated on version's RFC 9368 2 /
 * property 2 self-compatibility (this server only ever replies in the
 * version the client's own Initial used, never a different "switched-to"
 * one, so the check is defensive rather than a real branch point). Returns
 * 1, or 0 if version is unknown, the driver fails, or a buffer is too
 * small. */
static int srvboot_build_flight_bytes(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    u32                       version,
    u8*                       sh,
    u8*                       flight,
    srvboot_flight_bytes*     fb) {
  quic_obuf            sh_ob = quic_obuf_of(sh, SRVBOOT_SH_MAX);
  quic_obuf            fl_ob = quic_obuf_of(flight, SRVBOOT_HS_FLIGHT_MAX);
  quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
  if (!quic_version_compatible(version, version)) return 0;
  if (!wired_server_build_flight(conn->s, id->random, &fo)) return 0;
  *fb = (srvboot_flight_bytes){
      quic_span_of(sh, sh_ob.len), quic_span_of(flight, fl_ob.len)};
  return 1;
}

/* Build the server flight from the folded ClientHello and seal it, replying
 * in `version` -- the accepted Initial's own version (RFC 9368 2: no VN
 * round trip, so the server just answers in the version that arrived). */
static int srvboot_flight(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    u32                       version,
    u64                       ack_pn,
    wired_srvboot_out*        out) {
  u8                   sh[SRVBOOT_SH_MAX], flight[SRVBOOT_HS_FLIGHT_MAX];
  srvboot_flight_bytes fb;
  srvboot_server       sv = {
      conn->s, id, ack_pn,
      quic_span_of(conn->l->cli_scid, conn->l->cli_scid_len), version};
  if (!srvboot_build_flight_bytes(conn, id, version, sh, flight, &fb)) return 0;
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
  /* the accept flight's server Initial is pn 1 (srvboot_flight); partial
   * acks climb from 2 so the peer never mistakes the flight for a dup */
  a->ack_pn       = 2;
  a->alt_dcid_len = 0;
  a->zerortt_n    = 0;
}

/* Accumulated byte difference between two ids of the same length. */
static u8 srvboot_cid_diff(const u8* x, const u8* y, u8 len) {
  u8 diff = 0;
  for (u8 i = 0; i < len; i++) diff |= x[i] ^ y[i];
  return diff;
}

/* 1 if the len-byte id x equals the ylen-byte id y. */
static int srvboot_cid_match(const u8* x, u8 len, const u8* y, u8 ylen) {
  if (len != ylen) return 0;
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
static int srvboot_acc_same_dcid(const wired_srvboot_acc* a, quic_mspan dg) {
  wired_header h;
  if (!wired_header_parse(dg.p, dg.n, &h)) return 0;
  return srvboot_cid_match(h.dcid, h.dcid_len, a->hdr.dcid, a->hdr.dcid_len) ||
         srvboot_acc_alt_match(a, &h);
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
  if (!srvboot_is_long_initial(pkt.p[0], a->hdr.version)) return 0;
  if (!quic_initpkt_open_ver(odcid, a->hdr.version, pkt, &payload)) return 0;
  quic_crecv_collect(&a->cr, payload.p, payload.n);
  a->largest_pn = quic_u64_max(a->largest_pn, srvboot_initial_pn(pkt));
  a->opened++;
  return 1;
}

/* Coalesced packets per boot datagram (RFC 9000 12.2). */
#define SRVBOOT_ACC_PKTS 4

/* 1 if n is a usable connection-id length (nonzero, within the cap). */
static int srvboot_cid_len_ok(usz n) {
  return n != 0 && n <= WIRED_MAX_CID_LEN;
}

void wired_srvboot_acc_allow(wired_srvboot_acc* a, quic_span dcid) {
  if (!srvboot_cid_len_ok(dcid.n)) return;
  for (usz i = 0; i < dcid.n; i++) a->alt_dcid[i] = dcid.p[i];
  a->alt_dcid_len = (u8)dcid.n;
}

/* 1 once a has authenticated at least one Initial (something real to ack,
 * and a source address proven able to receive, RFC 9000 8.1). */
static int srvboot_acc_ackable(const wired_srvboot_acc* a) {
  return a->any && a->opened != 0;
}

usz wired_srvboot_partial_ack(
    wired_srvboot_acc* a, quic_span scid, u8* out, usz cap) {
  quic_obuf            ob = quic_obuf_of(out, cap);
  quic_srvwire_seal_in wi = {
      quic_span_of(a->hdr.dcid, a->hdr.dcid_len),
      quic_span_of(a->hdr.scid, a->hdr.scid_len),
      scid,
      a->ack_pn,
      (i64)a->largest_pn,
      quic_span_of(0, 0),
      0};
  if (!srvboot_acc_ackable(a)) return 0;
  if (!quic_srvwire_seal_initial_frames_lean(&wi, &ob)) return 0;
  a->ack_pn++;
  return ob.len;
}

int wired_srvboot_is_zerortt(const u8* dg, usz len) {
  if (!srvboot_is_initial_sized(dg, len)) return 0;
  return quic_packet_long_type(dg[0], quic_get_be32(dg + 1)) == QUIC_PT_0RTT;
}

/* 1 if a has room for one more buffered 0-RTT datagram of dg's size --
 * overflow past WIRED_SRVBOOT_ZERORTT_MAX or WIRED_SRVBOOT_ZERORTT_DG_MAX is
 * silently dropped (the client's own PTO resends it over 1-RTT once 0-RTT is
 * never confirmed, RFC 9000 13.3). */
static int srvboot_zerortt_fits(const wired_srvboot_acc* a, quic_mspan dg) {
  return a->zerortt_n < WIRED_SRVBOOT_ZERORTT_MAX &&
         dg.n <= WIRED_SRVBOOT_ZERORTT_DG_MAX;
}

/* RFC 9001 4.6.1: hold dg verbatim for wired_srvboot_acc_zerortt_take once
 * this boot's 0-RTT keys exist. */
static void srvboot_zerortt_buffer(wired_srvboot_acc* a, quic_mspan dg) {
  if (!srvboot_zerortt_fits(a, dg)) return;
  for (usz i = 0; i < dg.n; i++) a->zerortt_dg[a->zerortt_n][i] = dg.p[i];
  a->zerortt_len[a->zerortt_n] = dg.n;
  a->zerortt_n++;
}

/* Absorb every coalesced Initial packet in dg into a. Split out of
 * wired_srvboot_acc_feed so its own 0-RTT/Initial dispatch stays <=3. */
static int srvboot_acc_feed_initial(wired_srvboot_acc* a, quic_mspan dg) {
  const u8*    pkts[SRVBOOT_ACC_PKTS];
  usz          offs[SRVBOOT_ACC_PKTS], lens[SRVBOOT_ACC_PKTS], n, got = 0;
  quic_pktlist pl = {pkts, offs, lens, SRVBOOT_ACC_PKTS};
  if (!srvboot_acc_admit(a, dg)) return 0;
  n = quic_udploop_split(quic_span_of(dg.p, dg.n), &pl);
  for (usz i = 0; i < n; i++)
    got += (usz)srvboot_acc_take(a, quic_mspan_of(dg.p + offs[i], lens[i]));
  return got != 0;
}

int wired_srvboot_acc_feed(wired_srvboot_acc* a, quic_mspan dg) {
  if (wired_srvboot_is_zerortt(dg.p, dg.n)) {
    srvboot_zerortt_buffer(a, dg);
    return 1;
  }
  return srvboot_acc_feed_initial(a, dg);
}

usz wired_srvboot_acc_zerortt_count(const wired_srvboot_acc* a) {
  return a->zerortt_n;
}

quic_span wired_srvboot_acc_zerortt_take(const wired_srvboot_acc* a, usz i) {
  if (i >= a->zerortt_n) return quic_span_of(0, 0);
  return quic_span_of(a->zerortt_dg[i], a->zerortt_len[i]);
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
  return srvboot_flight(conn, id, a->hdr.version, a->largest_pn, out);
}

/* RFC 9001 4.8: 0x128 (TLS handshake_failure) when the caller has no more
 * specific quic_sdrv_last_error cause on hand. */
#define SRVBOOT_REFUSAL_DEFAULT_ERROR 0x128

/* error_code, or the generic fallback when the caller had no specific
 * cause (0). */
static u64 srvboot_refusal_error(u64 error_code) {
  if (error_code) return error_code;
  return SRVBOOT_REFUSAL_DEFAULT_ERROR;
}

usz wired_srvboot_refusal(
    const wired_srvboot_acc* a,
    quic_span                scid,
    u64                      error_code,
    u8*                      out,
    usz                      cap) {
  u8                    fr[8];
  quic_conn_close_frame f  = {0, srvboot_refusal_error(error_code), 0, 0, 0};
  usz                   fn = quic_frame_put_conn_close(fr, sizeof fr, &f);
  quic_obuf             ob = quic_obuf_of(out, cap);
  quic_srvwire_seal_in  wi = {
      quic_span_of(a->hdr.dcid, a->hdr.dcid_len),
      quic_span_of(a->hdr.scid, a->hdr.scid_len),
      scid,
      1,
      (i64)a->largest_pn,
      quic_span_of(fr, fn),
      0};
  if (fn == 0) return 0;
  if (!quic_srvwire_seal_initial_frames(&wi, &ob)) return 0;
  return ob.len;
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

/* 1 if v is neither a Version Negotiation packet's 0 (RFC 9000 6.1) nor a
 * version this server speaks (RFC 9368 5 supported set: v1, v2). */
static int srvboot_vn_alien(u32 v) {
  quic_vers_set s;
  if (v == 0) return 0;
  quic_vers_init(&s);
  return !quic_vers_supports(&s, v);
}

/* 1 if dg is a long-header datagram of an unsupported version. */
static int srvboot_vn_owed(quic_span dg) {
  return srvboot_vn_sized(dg) && srvboot_vn_alien(quic_get_be32(dg.p + 1));
}

usz wired_srvboot_vneg(quic_span dg, u8* out, usz cap) {
  quic_vers_set  s;
  wired_header   h;
  quic_vneg_desc d;
  if (!srvboot_vn_owed(dg)) return 0;
  if (!wired_header_parse(dg.p, dg.n, &h)) return 0;
  quic_vers_init(&s);
  d = (quic_vneg_desc){
      quic_span_of(h.dcid, h.dcid_len), quic_span_of(h.scid, h.scid_len),
      s.versions, s.n};
  return quic_vneg_respond(out, cap, &d);
}
