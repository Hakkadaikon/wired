#include "tls/handshake/roles/client/clientwire.h"

#include "app/http3/server/srvwire/wire.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "transport/packet/build/initpkt/initpkt.h"

/* RFC 9001 4 / 5: client real-wire codec. Seal own-direction (CLIENT_*),
 * open peer-direction (SERVER_*). */

#define CLIENTWIRE_CH_MAX 1024

/* A directional key plus its header-protection cipher, both derived together.
 */
typedef struct {
  const initial_keys* k;
  aes128              hp;
} cw_dirkey;

/* Fetch the directional key `which` from the client's schedule and initialize
 * its header-protection cipher. Returns 1, or 0 if the key is not derived. */
static int cw_dir_key(client* c, int which, cw_dirkey* dk) {
  if (!keysched_get(&c->tls.ks, which, &dk->k)) {
    return 0;
  }
  aes128_init(&dk->hp, dk->k->hp);
  return 1;
}

/* RFC 8446 4.1.2: build the raw ClientHello (the exact bytes the tlsdriver
 * emits: zero random, ALPN h3, initial_source_connection_id only), so the
 * Initial carries it in a single CRYPTO frame rather than a CRYPTO-in-CRYPTO
 * wrap. Delegates to the tlsdriver's raw-CH accessor so driver state (SNI) is
 * honored here too. */
static usz cw_client_hello(client* c, u8* ch, usz cap) {
  return tlsdriver_raw_client_hello(&c->tls, ch, cap);
}

/* RFC 9001 5.2 */
int client_build_initial_wire(
    client* c, const clientwire_hdr_in* hdr, wired_obuf* out) {
  u8  ch[CLIENTWIRE_CH_MAX];
  usz ch_len = 0;
  /* RFC 9000 7.3: our ClientHello names this Initial's SCID. */
  if (tlsdriver_set_iscid(&c->tls, hdr->scid)) {
    ch_len = cw_client_hello(c, ch, sizeof(ch));
  }
  if (ch_len == 0) {
    return 0;
  }
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
      0,
      0,
      0,
      0,
      0 /* v1 */};
  protect_keys pk;
  if (!cw_dir_key(c, KS_CLIENT_HS, &dk)) {
    return 0;
  }
  pk = (protect_keys){dk.k, &dk.hp, 0};
  return srvwire_seal_handshake(&pk, &si, out);
}

/* RFC 9001 5: open a server Handshake flight with SERVER_HS (peer direction).
 */
int client_open_handshake_wire(
    client* c, const appdata_pkt* in, wired_span* tls) {
  cw_dirkey    dk;
  protect_keys pk;
  (void)in->dcid_len;
  if (!cw_dir_key(c, KS_SERVER_HS, &dk)) {
    return 0;
  }
  pk = (protect_keys){dk.k, &dk.hp, 0};
  return srvwire_open_handshake(&pk, in->pkt, tls);
}
