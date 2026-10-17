#include "app/http3/server/srvboot/srvboot_impl.h"

static usz srvboot_chunk_len(usz remaining);
static int srvboot_seal_next(
    const srvboot_server* sv,
    wired_span            flight,
    usz*                  off,
    wired_srvboot_out*    out);
static int srvboot_seal_hs_flight(
    const srvboot_server* sv, wired_span flight, wired_srvboot_out* out);
static int srvboot_seal_flight(
    const srvboot_server*       sv,
    const srvboot_flight_bytes* fb,
    wired_srvboot_out*          out);
static int srvboot_build_flight_bytes(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    u32                       client_version,
    u32                       reply_version,
    u8*                       sh,
    u8*                       flight,
    srvboot_flight_bytes*     fb);

/* RFC 9000 13.2.1 / A.3: the opened Initial's packet number is cleartext once
 * header protection is off; recover it against the largest received so far
 * in this space. A retransmitted Initial arrives with pn > 0, and the
 * ServerHello Initial must acknowledge the number actually received or the
 * peer keeps retransmitting -- and once the partial-ClientHello ack raised
 * the peer's largest-acked, its retransmits truncate the wire pn below what
 * the raw value expresses (neqo: pn 731 in one byte after an ack of 729). */
u64 srvboot_initial_pn(wired_mspan dg, u64 largest_pn) {
  lhdr h;
  if (!lhdr_parse(wired_span_of(dg.p, dg.n), 1, &h)) return 0;
  return pnum_decode(dg.p + h.pn_off, lhdr_pn_len(dg.p[0]), largest_pn);
}

static usz srvboot_chunk_len(usz remaining) {
  return remaining < SRVBOOT_HS_CHUNK ? remaining : SRVBOOT_HS_CHUNK;
}

/* Seal the flight chunk at *off as its own Handshake packet (pn = datagram
 * index, CRYPTO offset = *off, RFC 9000 19.6) appended to out->flight,
 * recording its datagram length. Returns 1, 0 on overflow or a flight that
 * needs more than WIRED_SRVBOOT_FLIGHT_MAX datagrams. */
static int srvboot_seal_next(
    const srvboot_server* sv,
    wired_span            flight,
    usz*                  off,
    wired_srvboot_out*    out) {
  usz        n    = srvboot_chunk_len(flight.n - *off);
  wired_obuf tail = obuf_of(
      out->flight->p + out->flight->len, out->flight->cap - out->flight->len);
  wired_srvloop_send_in in = {
      sv->cli_scid,
      out->dgram_count,
      -1,
      wired_span_of(flight.p + *off, n),
      *off,
      0,
      0,
      0};
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
    const srvboot_server* sv, wired_span flight, wired_srvboot_out* out) {
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
  wired_srvloop_send_in in0 = {sv->cli_scid, sv->ini_pn,  (i64)sv->ack_pn,
                               fb->sh,       sv->ini_off, sv->ect0,
                               sv->ect1,     sv->ce};
  if (!wired_srvloop_send_initial_ver(sv->version, sv->s, &in0, out->initial))
    return 0;
  return srvboot_seal_hs_flight(sv, fb->flight, out);
}

/* Build the TLS server flight (ServerHello + Handshake messages) into fb's
 * backing buffers, to be sealed in reply_version -- gated on RFC 9368 2.3
 * compatibility with client_version, the version the client's own Initial
 * used (the driver only ever selects a compatible version, so the check is
 * defensive rather than a real branch point). Returns 1, or 0 if the
 * versions are incompatible, the driver fails, or a buffer is too small. */
static int srvboot_build_flight_bytes(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    u32                       client_version,
    u32                       reply_version,
    u8*                       sh,
    u8*                       flight,
    srvboot_flight_bytes*     fb) {
  wired_obuf      sh_ob = obuf_of(sh, SRVBOOT_SH_MAX);
  wired_obuf      fl_ob = obuf_of(flight, SRVBOOT_HS_FLIGHT_MAX);
  sdrv_flight_out fo    = {&sh_ob, &fl_ob};
  if (!version_compatible(client_version, reply_version)) return 0;
  if (!wired_server_build_flight(conn->s, id->random, &fo)) return 0;
  *fb = (srvboot_flight_bytes){
      wired_span_of(sh, sh_ob.len), wired_span_of(flight, fl_ob.len)};
  return 1;
}

/* RFC 9000 12.3: the accept flight's server Initial is pn 1 -- unless the
 * Initial pn space has already moved past it (a HelloRetryRequest or a
 * partial-ClientHello ACK went out first); then the flight takes the next
 * unused pn from the shared counter. Falling back to pn 1 AFTER an ACK at
 * pn 2 would send the space backwards, and a peer that treats the space as
 * continuous (it is -- RFC 9368 2.3 keeps the connection, and neqo enforces
 * it across a compatible version switch) discards the flight as too old. */
u64 wired_srvboot_flight_pn(wired_srvboot_acc* a) {
  return (a->hrr_off || a->ack_pn > 2) ? a->ack_pn++ : 1;
}

/* Build the server flight from the folded ClientHello and seal it, replying
 * in the connection's wire version -- the compatible version the driver
 * selected from the ClientHello's version_information, else the accepted
 * Initial's own version (RFC 9368 2.3: the switch happens in the server's
 * first flight, no VN round trip). Everything connection-specific -- ack
 * target, Initial pn, crypto-stream offset, ECN counts -- comes from the
 * accumulator. */
int srvboot_flight(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_srvboot_acc*        a,
    wired_srvboot_out*        out) {
  u8                   sh[SRVBOOT_SH_MAX], flight[SRVBOOT_HS_FLIGHT_MAX];
  srvboot_flight_bytes fb;
  u32                  reply_version = sdrv_wire_version(&conn->s->sdrv);
  srvboot_server       sv            = {
      conn->s,       id,
      a->largest_pn, wired_span_of(conn->l->cli_scid, conn->l->cli_scid_len),
      reply_version, wired_srvboot_flight_pn(a),
      a->ini_tx_off, a->ecn_ect0,
      a->ecn_ect1,   a->ecn_ce};
  if (!srvboot_build_flight_bytes(
          conn, id, a->hdr.version, reply_version, sh, flight, &fb))
    return 0;
  if (!srvboot_seal_flight(&sv, &fb, out)) return 0;
  /* RFC 9000 12.3: later Handshake sends continue after the flight's packet
   * numbers 0..dgram_count-1. */
  conn->l->hs_tx_pn = out->dgram_count;
  return 1;
}
