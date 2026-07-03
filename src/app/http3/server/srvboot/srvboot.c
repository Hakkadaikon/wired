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
    quic_crecv *cr, quic_span payload, quic_span *msg) {
  quic_crecv_init(cr);
  if (!quic_crecv_collect(cr, payload.p, payload.n)) return 0;
  if (!quic_crecv_complete_message(cr)) return 0;
  quic_crecv_message(cr, &msg->p, &msg->n);
  return 1;
}

/* RFC 9000 17.2: the DCID is unprotected at the front, so open the Initial and
 * recover the ClientHello. */
static int srvboot_open_initial(quic_mspan dg, quic_crecv *cr, quic_span *msg) {
  quic_span payload;
  if (!wired_srvboot_is_initial(dg.p, dg.n)) return 0;
  if (!quic_initpkt_open(quic_span_of(dg.p + 6, dg.p[5]), dg, &payload))
    return 0;
  return srvboot_collect_ch(cr, payload, msg);
}

/* Init the server and its loop. The client's DCID (this Initial's DCID) is the
 * ODCID for Initial keys (RFC 9001 5.2); the client's SCID is the DCID the
 * server writes back and the loop is seeded with (RFC 9000 17.2 / 5.1). */
static int srvboot_init(
    const wired_srvboot_conn *conn,
    const wired_srvboot_id   *id,
    const wired_header       *h) {
  wired_server_init_in in = {
      id->priv, id->pub, id->cert_seed, id->chain, id->chain_count};
  wired_server_init(conn->s, &in);
  if (!wired_server_set_cids(
          conn->s, quic_span_of(h->dcid, h->dcid_len),
          quic_span_of(id->scid, id->scid_len)))
    return 0;
  return wired_srvloop_init(conn->l, h->scid, h->scid_len);
}

/* RFC 9000 13.2.1: the client's first Initial is packet number 0; the server
 * acknowledges it in the ServerHello Initial so the peer stops retransmitting.
 * The Handshake space has no received packet yet, so its flight carries no ACK
 * (-1). */
#define SRVBOOT_CLIENT_INITIAL_PN 0

/* The two pieces of a server flight: the ServerHello (Initial space) and the
 * Handshake-space flight (Certificate/CertificateVerify/Finished). */
typedef struct {
  quic_span sh;
  quic_span flight;
} srvboot_flight_bytes;

/* The server and its fixed identity, threaded together through flight
 * sealing (they always travel as a pair). */
typedef struct {
  wired_server           *s;
  const wired_srvboot_id *id;
} srvboot_server;

/* Seal the ServerHello into a server Initial and the flight into a Handshake
 * packet, concatenated into out. Returns 1, 0 on overflow. */
static int srvboot_seal_flight(
    const srvboot_server *sv, const srvboot_flight_bytes *fb, quic_obuf *out) {
  wired_srvloop_send_in in0 = {
      quic_span_of(sv->id->scid, sv->id->scid_len), 1,
      SRVBOOT_CLIENT_INITIAL_PN, fb->sh};
  wired_srvloop_send_in in1 = {
      quic_span_of(sv->id->scid, sv->id->scid_len), 0, -1, fb->flight};
  quic_obuf ob0 = quic_obuf_of(out->p, out->cap);
  quic_obuf ob1;
  if (!wired_srvloop_send_initial(sv->s, &in0, &ob0)) return 0;
  ob1 = quic_obuf_of(out->p + ob0.len, out->cap - ob0.len);
  if (!wired_srvloop_send_handshake(sv->s, &in1, &ob1)) return 0;
  out->len = ob0.len + ob1.len;
  return 1;
}

/* Build the server flight from the folded ClientHello and seal it. */
static int srvboot_flight(
    wired_server *s, const wired_srvboot_id *id, quic_obuf *out) {
  u8                   sh[512], flight[2048];
  quic_obuf            sh_ob = quic_obuf_of(sh, sizeof sh);
  quic_obuf            fl_ob = quic_obuf_of(flight, sizeof flight);
  quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
  srvboot_flight_bytes fb;
  srvboot_server       sv = {s, id};
  if (!wired_server_build_flight(s, id->random, &fo)) return 0;
  fb = (srvboot_flight_bytes){
      quic_span_of(sh, sh_ob.len), quic_span_of(flight, fl_ob.len)};
  return srvboot_seal_flight(&sv, &fb, out);
}

/* Where srvboot_read_initial recovers the reassembly state, header, and
 * folded ClientHello. cr must outlive ch: quic_crecv_message() returns a view
 * into cr's own reassembly buffer, so the caller owns cr's storage. */
typedef struct {
  quic_crecv   *cr;
  wired_header *h;
  quic_span    *ch;
} srvboot_read_out;

/* Recover the ClientHello and parse the header from the Initial datagram. */
static int srvboot_read_initial(quic_mspan dgram, const srvboot_read_out *out) {
  if (!srvboot_open_initial(dgram, out->cr, out->ch)) return 0;
  return wired_header_parse(dgram.p, dgram.n, out->h);
}

/* Open the Initial, init the server/loop, and fold the ClientHello — up to
 * (not including) building the flight. */
static int srvboot_accept_ch(
    const wired_srvboot_conn *conn,
    const wired_srvboot_id   *id,
    quic_mspan                dgram) {
  wired_header     h;
  quic_crecv       cr;
  quic_span        ch  = quic_span_of(0, 0);
  srvboot_read_out out = {&cr, &h, &ch};
  if (!srvboot_read_initial(dgram, &out)) return 0;
  if (!srvboot_init(conn, id, &h)) return 0;
  return wired_server_recv_initial(conn->s, ch.p, ch.n);
}

int wired_srvboot_accept(
    const wired_srvboot_conn *conn,
    const wired_srvboot_in   *in,
    quic_obuf                *out) {
  if (!srvboot_accept_ch(conn, in->id, in->dgram)) return 0;
  return srvboot_flight(conn->s, in->id, out);
}
