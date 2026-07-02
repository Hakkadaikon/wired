#include "tls/handshake/roles/client/clientwire.h"

#include "app/http3/server/srvwire/wire.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "transport/packet/build/initpkt/initpkt.h"
#include "transport/stream/data/appdata/app_recv.h"
#include "transport/stream/data/appdata/app_send.h"

/* RFC 9001 4 / 5: client real-wire codec. Seal own-direction (CLIENT_*),
 * open peer-direction (SERVER_*). */

#define QUIC_CLIENTWIRE_CH_MAX 1024

/* Fetch the directional key `which` from the client's schedule and initialize
 * its header-protection cipher. Returns 1, or 0 if the key is not derived. */
static int cw_dir_key(
    quic_client *c, int which, const quic_initial_keys **k, quic_aes128 *hp) {
  if (!quic_keysched_get(&c->tls.ks, which, k)) return 0;
  quic_aes128_init(hp, (*k)->hp);
  return 1;
}

/* RFC 8446 4.1.2: build the raw ClientHello (the exact bytes the tlsdriver
 * emits: zero random, ALPN h3, empty transport parameters), so the Initial
 * carries it in a single CRYPTO frame rather than a CRYPTO-in-CRYPTO wrap.
 * Delegates to the tlsdriver's raw-CH accessor so driver state (SNI) is
 * honored here too. */
static usz cw_client_hello(quic_client *c, u8 *ch, usz cap) {
  return quic_tlsdriver_raw_client_hello(&c->tls, ch, cap);
}

/* RFC 9001 5.2 */
int quic_client_build_initial_wire(
    quic_client *c,
    const u8    *dcid,
    u8           dcid_len,
    const u8    *scid,
    u8           scid_len,
    u64          pn,
    u8          *out,
    usz          cap,
    usz         *out_len) {
  u8  ch[QUIC_CLIENTWIRE_CH_MAX];
  usz ch_len = cw_client_hello(c, ch, sizeof(ch));
  if (ch_len == 0) return 0;
  quic_initpkt_desc d = {
      quic_span_of(dcid, dcid_len), quic_span_of(scid, scid_len),
      quic_span_of(ch, ch_len), pn};
  quic_obuf o = quic_obuf_of(out, cap);
  if (!quic_initpkt_build(&d, &o)) return 0;
  *out_len = o.len;
  return 1;
}

/* RFC 9001 5.2: open the server Initial with the server-direction keys. */
int quic_client_open_initial_wire(
    const u8  *dcid,
    u8         dcid_len,
    u8        *pkt,
    usz        len,
    u64        pn,
    const u8 **tls,
    usz       *tls_len) {
  return quic_srvwire_open_initial(dcid, dcid_len, pkt, len, pn, tls, tls_len);
}

/* RFC 9001 5: seal a Handshake flight with CLIENT_HS (own direction). */
int quic_client_seal_handshake_wire(
    quic_client *c,
    const u8    *dcid,
    u8           dcid_len,
    const u8    *scid,
    u8           scid_len,
    u64          pn,
    const u8    *tls,
    usz          tls_len,
    u8          *out,
    usz          cap,
    usz         *out_len) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  if (!cw_dir_key(c, QUIC_KS_CLIENT_HS, &k, &hp)) return 0;
  return quic_srvwire_seal_handshake(
      k, &hp, dcid, dcid_len, scid, scid_len, pn, -1, tls, tls_len, out, cap,
      out_len);
}

/* RFC 9001 5: open a server Handshake flight with SERVER_HS (peer direction).
 */
int quic_client_open_handshake_wire(
    quic_client *c,
    u8          *pkt,
    usz          len,
    u8           dcid_len,
    const u8   **tls,
    usz         *tls_len) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  if (!cw_dir_key(c, QUIC_KS_SERVER_HS, &k, &hp)) return 0;
  return quic_srvwire_open_handshake(k, &hp, pkt, len, dcid_len, tls, tls_len);
}

/* RFC 9001 5: send 1-RTT application data with CLIENT_AP (own direction). */
int quic_client_send_appdata_wire(
    quic_client *c,
    const u8    *dcid,
    u8           dcid_len,
    u64          pn,
    u64          stream_id,
    const u8    *data,
    usz          len,
    int          fin,
    u8          *out,
    usz          cap,
    usz         *out_len) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  quic_protect_keys        pk;
  quic_appdata_tx          tx;
  quic_obuf                o = quic_obuf_of(out, cap);
  if (!cw_dir_key(c, QUIC_KS_CLIENT_AP, &k, &hp)) return 0;
  pk = (quic_protect_keys){k, &hp};
  tx = (quic_appdata_tx){
      quic_span_of(dcid, dcid_len), pn, stream_id, quic_span_of(data, len),
      fin};
  if (!quic_appdata_send(&pk, &tx, &o)) return 0;
  *out_len = o.len;
  return 1;
}

/* RFC 9000 5.1: a short-header 1-RTT packet's DCID (pkt[1 .. 1+scid_len]) must
 * equal the connection id we offered as our SCID — a packet whose DCID does not
 * route to us is for another connection and is dropped (this is the check curl
 * applies, so the in-tree client catches a server that writes the wrong DCID).
 */
static int cw_dcid_is_ours(
    const u8 *pkt, usz len, const u8 *scid, u8 scid_len) {
  u8 d = 0;
  if (len < 1u + (usz)scid_len) return 0;
  for (u8 i = 0; i < scid_len; i++) d |= pkt[1 + i] ^ scid[i];
  return d == 0;
}

/* RFC 9000 5.1 / RFC 9001 5: the DCID routes to us and the SERVER_AP key is
 * derived; both gate opening the packet. */
static int cw_recv_ok(
    quic_client              *c,
    const u8                 *pkt,
    usz                       len,
    const u8                 *scid,
    u8                        scid_len,
    const quic_initial_keys **k,
    quic_aes128              *hp) {
  if (!cw_dcid_is_ours(pkt, len, scid, scid_len)) return 0;
  return cw_dir_key(c, QUIC_KS_SERVER_AP, k, hp);
}

/* RFC 9001 5: open a 1-RTT packet with SERVER_AP (peer direction), but first
 * drop it unless its DCID matches our SCID (RFC 9000 5.1). */
int quic_client_recv_appdata_wire(
    quic_client *c,
    u8          *pkt,
    usz          len,
    const u8    *scid,
    u8           scid_len,
    u64         *stream_id,
    u64         *offset,
    const u8   **data,
    usz         *data_len,
    int         *fin) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  quic_protect_keys        pk;
  quic_appdata_pkt         ap;
  quic_stream_frame        f;
  if (!cw_recv_ok(c, pkt, len, scid, scid_len, &k, &hp)) return 0;
  pk = (quic_protect_keys){k, &hp};
  ap = (quic_appdata_pkt){quic_mspan_of(pkt, len), scid_len};
  if (!quic_appdata_recv(&pk, &ap, &f)) return 0;
  *stream_id = f.stream_id;
  *offset    = f.offset;
  *data      = f.data;
  *data_len  = (usz)f.length;
  *fin       = f.fin;
  return 1;
}
