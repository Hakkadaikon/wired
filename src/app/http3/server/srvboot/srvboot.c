#include "app/http3/server/srvboot/srvboot.h"

#include "app/http3/server/srvloop/send.h"
#include "transport/conn/loop/crecv/collect.h"
#include "transport/conn/loop/crecv/message.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/header/packet/header.h"

/* RFC 9000 17.2: byte0 has the long-header bit set and Initial type bits 00. */
static int srvboot_is_long_initial(u8 byte0) {
  return (byte0 & 0x80) != 0 && (byte0 & 0x30) == 0;
}

int wired_srvboot_is_initial(const u8 *dg, usz len) {
  if (len < 6 || !srvboot_is_long_initial(dg[0])) return 0;
  return len >= (usz)6 + dg[5];
}

/* Reassemble the ClientHello from the opened Initial payload's CRYPTO frame(s)
 * (peers may lead with PADDING/ACK and split the CH, RFC 9000 12.4 / 19.6). */
static int srvboot_collect_ch(
    quic_crecv *cr, const u8 *payload, usz plen, const u8 **msg, usz *mlen) {
  quic_crecv_init(cr);
  if (!quic_crecv_collect(cr, payload, plen)) return 0;
  if (!quic_crecv_complete_message(cr)) return 0;
  quic_crecv_message(cr, msg, mlen);
  return 1;
}

/* RFC 9000 17.2: the DCID is unprotected at the front, so open the Initial and
 * recover the ClientHello. */
static int srvboot_open_initial(
    u8 *dg, usz len, quic_crecv *cr, const u8 **msg, usz *mlen) {
  quic_span payload;
  if (!wired_srvboot_is_initial(dg, len)) return 0;
  if (!quic_initpkt_open(
          quic_span_of(dg + 6, dg[5]), quic_mspan_of(dg, len), &payload))
    return 0;
  return srvboot_collect_ch(cr, payload.p, payload.n, msg, mlen);
}

/* Init the server and its loop. The client's DCID (this Initial's DCID) is the
 * ODCID for Initial keys (RFC 9001 5.2); the client's SCID is the DCID the
 * server writes back and the loop is seeded with (RFC 9000 17.2 / 5.1). */
static int srvboot_init(
    quic_server            *s,
    quic_srvloop           *l,
    const wired_srvboot_id *id,
    const quic_header      *h) {
  quic_server_init_in in = {id->priv, id->pub, id->cert_seed, quic_span_of(0, 0)};
  quic_server_init(s, &in);
  if (!quic_server_set_cids(
          s, quic_span_of(h->dcid, h->dcid_len),
          quic_span_of(id->scid, id->scid_len)))
    return 0;
  return quic_srvloop_init(l, h->scid, h->scid_len);
}

/* RFC 9000 13.2.1: the client's first Initial is packet number 0; the server
 * acknowledges it in the ServerHello Initial so the peer stops retransmitting.
 * The Handshake space has no received packet yet, so its flight carries no ACK
 * (-1). */
#define SRVBOOT_CLIENT_INITIAL_PN 0

/* Seal the ServerHello into a server Initial and the flight into a Handshake
 * packet, concatenated into out. Returns 1, 0 on overflow. */
static int srvboot_seal_flight(
    quic_server            *s,
    const wired_srvboot_id *id,
    const u8               *sh,
    usz                     shl,
    const u8               *flight,
    usz                     fll,
    u8                     *out,
    usz                     cap,
    usz                    *out_len) {
  usz n0 = 0, n1 = 0;
  if (!quic_srvloop_send_initial(
          s, id->scid, id->scid_len, 1, SRVBOOT_CLIENT_INITIAL_PN, sh, shl, out,
          cap, &n0))
    return 0;
  if (!quic_srvloop_send_handshake(
          s, id->scid, id->scid_len, 0, -1, flight, fll, out + n0, cap - n0,
          &n1))
    return 0;
  *out_len = n0 + n1;
  return 1;
}

/* Build the server flight from the folded ClientHello and seal it. */
static int srvboot_flight(
    quic_server            *s,
    const wired_srvboot_id *id,
    u8                     *out,
    usz                     cap,
    usz                    *out_len) {
  u8                   sh[512], flight[2048];
  quic_obuf            sh_ob = quic_obuf_of(sh, sizeof sh);
  quic_obuf            fl_ob = quic_obuf_of(flight, sizeof flight);
  quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
  if (!quic_server_build_flight(s, id->random, &fo)) return 0;
  return srvboot_seal_flight(
      s, id, sh, sh_ob.len, flight, fl_ob.len, out, cap, out_len);
}

/* Recover the ClientHello and parse the header from the Initial datagram.
 * cr must outlive ch/ch_len: quic_crecv_message() returns a view into cr's
 * own reassembly buffer, so the caller owns cr's storage. */
static int srvboot_read_initial(
    u8 *dgram, usz len, quic_crecv *cr, quic_header *h, const u8 **ch,
    usz *ch_len) {
  if (!srvboot_open_initial(dgram, len, cr, ch, ch_len)) return 0;
  return quic_header_parse(dgram, len, h);
}

/* Open the Initial, init the server/loop, and fold the ClientHello — up to
 * (not including) building the flight. */
static int srvboot_accept_ch(
    quic_server            *s,
    quic_srvloop           *l,
    const wired_srvboot_id *id,
    u8                     *dgram,
    usz                     len) {
  quic_header h;
  quic_crecv  cr;
  const u8   *ch;
  usz         ch_len;
  if (!srvboot_read_initial(dgram, len, &cr, &h, &ch, &ch_len)) return 0;
  if (!srvboot_init(s, l, id, &h)) return 0;
  return quic_server_recv_initial(s, ch, ch_len);
}

int wired_srvboot_accept(
    quic_server            *s,
    quic_srvloop           *l,
    const wired_srvboot_id *id,
    u8                     *dgram,
    usz                     len,
    u8                     *out,
    usz                     cap,
    usz                    *out_len) {
  if (!srvboot_accept_ch(s, l, id, dgram, len)) return 0;
  return srvboot_flight(s, id, out, cap, out_len);
}
