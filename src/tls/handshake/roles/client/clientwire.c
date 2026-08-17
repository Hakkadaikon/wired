#include "tls/handshake/roles/client/clientwire.h"

#include "app/http3/server/srvwire/wire.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "transport/packet/build/initpkt/initpkt.h"
#include "transport/stream/data/appdata/app_recv.h"
#include "transport/stream/data/appdata/app_send.h"

/* RFC 9001 4 / 5: client real-wire codec. Seal own-direction (CLIENT_*),
 * open peer-direction (SERVER_*). */

#define QUIC_CLIENTWIRE_CH_MAX 1024

/* A directional key plus its header-protection cipher, both derived together.
 */
typedef struct {
  const initial_keys* k;
  aes128              hp;
} cw_dirkey;

/* Fetch the directional key `which` from the client's schedule and initialize
 * its header-protection cipher. Returns 1, or 0 if the key is not derived. */
static int cw_dir_key(client* c, int which, cw_dirkey* dk) {
  if (!keysched_get(&c->tls.ks, which, &dk->k)) return 0;
  aes128_init(&dk->hp, dk->k->hp);
  return 1;
}

/* RFC 8446 4.1.2: build the raw ClientHello (the exact bytes the tlsdriver
 * emits: zero random, ALPN h3, empty transport parameters), so the Initial
 * carries it in a single CRYPTO frame rather than a CRYPTO-in-CRYPTO wrap.
 * Delegates to the tlsdriver's raw-CH accessor so driver state (SNI) is
 * honored here too. */
static usz cw_client_hello(client* c, u8* ch, usz cap) {
  return tlsdriver_raw_client_hello(&c->tls, ch, cap);
}

/* RFC 9001 5.2 */
int client_build_initial_wire(
    client* c, const clientwire_hdr_in* hdr, wired_obuf* out) {
  u8  ch[QUIC_CLIENTWIRE_CH_MAX];
  usz ch_len = cw_client_hello(c, ch, sizeof(ch));
  if (ch_len == 0) return 0;
  initpkt_desc d = {
      hdr->dcid, hdr->scid, wired_span_of(ch, ch_len), hdr->pn, 0};
  return initpkt_build(&d, out);
}

/* RFC 9001 5.2: open the server Initial with the server-direction keys. */
int client_open_initial_wire(const clientwire_open_in* in, wired_span* tls) {
  srvwire_open_initial_in oin = {in->dcid, in->pn};
  return srvwire_open_initial(&oin, in->pkt, tls);
}

/* RFC 9001 5: seal a Handshake flight with CLIENT_HS (own direction). The
 * key-derivation dcid slot is unused (keys come from the schedule); in->
 * hdr.dcid is the header's DCID. */
int client_seal_handshake_wire(
    client* c, const clientwire_seal_in* in, wired_obuf* out) {
  cw_dirkey       dk;
  srvwire_seal_in si = {
      wired_span_of((const u8*)0, 0),
      in->hdr.dcid,
      in->hdr.scid,
      in->hdr.pn,
      -1,
      in->tls,
      0};
  protect_keys pk;
  if (!cw_dir_key(c, QUIC_KS_CLIENT_HS, &dk)) return 0;
  pk = (protect_keys){dk.k, &dk.hp};
  return srvwire_seal_handshake(&pk, &si, out);
}

/* RFC 9001 5: open a server Handshake flight with SERVER_HS (peer direction).
 */
int client_open_handshake_wire(
    client* c, const appdata_pkt* in, wired_span* tls) {
  cw_dirkey    dk;
  protect_keys pk;
  (void)in->dcid_len;
  if (!cw_dir_key(c, QUIC_KS_SERVER_HS, &dk)) return 0;
  pk = (protect_keys){dk.k, &dk.hp};
  return srvwire_open_handshake(&pk, in->pkt, tls);
}

/* RFC 9001 5: send 1-RTT application data with CLIENT_AP (own direction). */
int client_send_appdata_wire(client* c, const appdata_tx* in, wired_obuf* out) {
  cw_dirkey    dk;
  protect_keys pk;
  if (!cw_dir_key(c, QUIC_KS_CLIENT_AP, &dk)) return 0;
  pk = (protect_keys){dk.k, &dk.hp};
  return appdata_send(&pk, in, out);
}

/* RFC 9000 5.1: a short-header 1-RTT packet's DCID (pkt[1 .. 1+scid_len]) must
 * equal the connection id we offered as our SCID — a packet whose DCID does not
 * route to us is for another connection and is dropped (this is the check curl
 * applies, so the in-tree client catches a server that writes the wrong DCID).
 */
static int cw_dcid_is_ours(wired_mspan pkt, wired_span scid) {
  u8 d = 0;
  if (pkt.n < 1u + scid.n) return 0;
  for (usz i = 0; i < scid.n; i++) d |= pkt.p[1 + i] ^ scid.p[i];
  return d == 0;
}

/* RFC 9000 5.1 / RFC 9001 5: the DCID routes to us and the SERVER_AP key is
 * derived; both gate opening the packet. */
static int cw_recv_ok(client* c, const clientwire_recv_in* in, cw_dirkey* dk) {
  if (!cw_dcid_is_ours(in->pkt, in->scid)) return 0;
  return cw_dir_key(c, QUIC_KS_SERVER_AP, dk);
}

/* RFC 9001 5: open a 1-RTT packet with SERVER_AP (peer direction), but first
 * drop it unless its DCID matches our SCID (RFC 9000 5.1). */
int client_recv_appdata_wire(
    client* c, const clientwire_recv_in* in, stream_frame* out) {
  cw_dirkey    dk;
  protect_keys pk;
  appdata_pkt  ap;
  if (!cw_recv_ok(c, in, &dk)) return 0;
  pk = (protect_keys){dk.k, &dk.hp};
  ap = (appdata_pkt){in->pkt, (u8)in->scid.n};
  return appdata_recv(&pk, &ap, out);
}
