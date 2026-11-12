#include "app/http3/server/srvwire/wire.h"
#include "test.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/client/clientwire.h"
#include "tls/keys/schedule_drive/keyschedule.h"
#include "transport/packet/build/initpkt/initopen.h"

/* RFC 9001 4 / 5, WireHS: the client real-wire path seals with its own
 * direction (CLIENT_*) and opens with the peer direction (SERVER_*). */

static const u8 cw_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
static const u8 cw_scid[4] = {0x11, 0x22, 0x33, 0x44};

/* Drive a fresh keysched to the master stage so all four directional keys
 * (CLIENT_HS/SERVER_HS/CLIENT_AP/SERVER_AP) are derived, then plant it in c. */
static void cw_derive_keys(client* c) {
  u8 ecdhe[32], tr[] = "ClientHello||ServerHello";
  for (usz i = 0; i < 32; i++) {
    ecdhe[i] = (u8)(1 + i);
  }
  keysched_init(&c->tls.ks);
  CHECK(
      keysched_advance_handshake(
          &c->tls.ks, wired_span_of(ecdhe, 32),
          wired_span_of(tr, sizeof(tr))) == 1);
  CHECK(keysched_advance_master(&c->tls.ks, tr, sizeof(tr)) == 1);
}

/* RFC 9001 5.2: client seals its real ClientHello into a protected Initial.
 * The peer opens it with the (client-direction) Initial keys derived from the
 * same DCID and recovers a CRYPTO frame carrying the ClientHello (type 0x01).
 */
static void test_cw_initial_roundtrip(void) {
  client            c;
  u8                priv[32], pub[32], pkt[1300];
  wired_obuf        ob  = obuf_of(pkt, sizeof(pkt));
  clientwire_hdr_in hdr = {
      wired_span_of(cw_dcid, 8), wired_span_of(cw_scid, 4), 0};
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(7 + i);
  }
  wired_x25519_base(pub, priv);
  tlsdriver_init(&c.tls, priv, pub, 0);
  CHECK(client_build_initial_wire(&c, &hdr, &ob) == 1);
  CHECK(ob.len == 1200);
  wired_span fv;
  CHECK(
      initpkt_open(
          wired_span_of(cw_dcid, 8), wired_mspan_of(pkt, ob.len), &fv) == 1);
  CHECK(fv.p[0] == 0x06);          /* CRYPTO frame */
  CHECK(fv.p[1] == 0x00);          /* offset 0 */
  CHECK((fv.p[2] & 0xc0) == 0x40); /* 2-byte length varint */
  CHECK(fv.p[4] == 0x01);          /* ClientHello after the header */
}

/* RFC 9001 5.2: client opens a server Initial sealed by the server codec. */
static void test_cw_open_server_initial(void) {
  const u8        sh[] = {0x02, 0x00, 0x00, 0x02, 0xab, 0xcd};
  u8              pkt[1300];
  wired_span      tls;
  wired_obuf      ob = obuf_of(pkt, sizeof(pkt));
  srvwire_seal_in in = {
      wired_span_of(cw_dcid, 8),
      wired_span_of(cw_dcid, 8),
      wired_span_of(cw_scid, 4),
      0,
      -1,
      wired_span_of(sh, sizeof(sh)),
      0,
      0,
      0,
      0,
      0};
  CHECK(srvwire_seal_initial(&in, &ob) == 1);
  {
    clientwire_open_in oin = {
        wired_span_of(cw_dcid, 8), wired_mspan_of(pkt, ob.len), 0};
    CHECK(client_open_initial_wire(&oin, &tls) == 1);
  }
  CHECK(tls.n == sizeof(sh));
  for (usz i = 0; i < sizeof(sh); i++) {
    CHECK(tls.p[i] == sh[i]);
  }
}

/* RFC 9001 5: client seals a Handshake flight with CLIENT_HS; the peer opens it
 * with the client-direction key. Then client opens a SERVER_HS-sealed flight.
 */
static void test_cw_handshake_roundtrip(void) {
  client              c;
  const u8            fin[] = {0x14, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03};
  u8                  pkt[512];
  usz                 total = 0;
  wired_span          tls;
  const initial_keys *chs, *shs;
  aes128              hp;
  clientwire_seal_in  sin = {
      {wired_span_of(cw_dcid, 8), wired_span_of(cw_scid, 4), 0},
      wired_span_of(fin, sizeof(fin))};
  wired_obuf ob = obuf_of(pkt, sizeof(pkt));
  cw_derive_keys(&c);

  /* client seals with CLIENT_HS; peer opens with the same client key. */
  CHECK(client_seal_handshake_wire(&c, &sin, &ob) == 1);
  total = ob.len;
  CHECK(keysched_get(&c.tls.ks, KS_CLIENT_HS, &chs) == 1);
  aes128_init(&hp, chs->hp);
  {
    wired_span   sp;
    protect_keys pk = {chs, &hp, 0};
    CHECK(srvwire_open_handshake(&pk, wired_mspan_of(pkt, total), &sp) == 1);
    CHECK(sp.n == sizeof(fin));
  }

  /* client opens a flight sealed with SERVER_HS (peer direction). */
  CHECK(keysched_get(&c.tls.ks, KS_SERVER_HS, &shs) == 1);
  aes128_init(&hp, shs->hp);
  {
    wired_obuf      ob2 = obuf_of(pkt, sizeof(pkt));
    srvwire_seal_in in  = {
        wired_span_of((const u8*)0, 0),
        wired_span_of(cw_dcid, 8),
        wired_span_of(cw_scid, 4),
        0,
        -1,
        wired_span_of(fin, sizeof(fin)),
        0,
        0,
        0,
        0,
        0};
    protect_keys pk = {shs, &hp, 0};
    CHECK(srvwire_seal_handshake(&pk, &in, &ob2) == 1);
    total = ob2.len;
  }
  {
    appdata_pkt oin = {wired_mspan_of(pkt, total), 8};
    CHECK(client_open_handshake_wire(&c, &oin, &tls) == 1);
  }
  CHECK(tls.n == sizeof(fin));
  for (usz i = 0; i < sizeof(fin); i++) {
    CHECK(tls.p[i] == fin[i]);
  }
}

/* WireHS negative: a client-sealed (CLIENT_HS) Handshake packet must NOT open
 * with the client's own open key (SERVER_HS); wrong direction fails AEAD. */
static void test_cw_wrong_direction_fails(void) {
  client             c;
  const u8           fin[] = {0x14, 0x00, 0x00, 0x01, 0x09};
  u8                 pkt[512];
  wired_span         tls;
  clientwire_seal_in sin = {
      {wired_span_of(cw_dcid, 8), wired_span_of(cw_scid, 4), 0},
      wired_span_of(fin, sizeof(fin))};
  wired_obuf ob = obuf_of(pkt, sizeof(pkt));
  cw_derive_keys(&c);
  CHECK(client_seal_handshake_wire(&c, &sin, &ob) == 1);
  /* opening own-sealed packet with the peer-direction open key must fail. */
  {
    appdata_pkt oin = {wired_mspan_of(pkt, ob.len), 8};
    CHECK(client_open_handshake_wire(&c, &oin, &tls) == 0);
  }
}

/* RFC 9001 4.1.4: no Handshake protection before those keys are derived;
 * RFC 9000 17.2: a 21-byte SCID is not a connection ID. */
static void test_cw_rejects_before_keys_and_bad_cids(void) {
  client             c;
  const u8           fin[] = {0x14, 0x00, 0x00, 0x01, 0x09};
  u8                 pkt[512], priv[32] = {7}, pub[32], long_cid[21] = {0};
  wired_span         tls;
  wired_obuf         ob  = obuf_of(pkt, sizeof(pkt));
  clientwire_seal_in sin = {
      {wired_span_of(cw_dcid, 8), wired_span_of(cw_scid, 4), 0},
      wired_span_of(fin, sizeof(fin))};
  appdata_pkt       oin = {wired_mspan_of(pkt, 64), 8};
  clientwire_hdr_in hdr = {
      wired_span_of(cw_dcid, 8), wired_span_of(long_cid, 21), 0};
  wired_x25519_base(pub, priv);
  tlsdriver_init(&c.tls, priv, pub, 0);
  CHECK(client_seal_handshake_wire(&c, &sin, &ob) == 0);
  CHECK(client_open_handshake_wire(&c, &oin, &tls) == 0);
  CHECK(client_build_initial_wire(&c, &hdr, &ob) == 0);
}

void test_client_wire(void) {
  test_cw_rejects_before_keys_and_bad_cids();
  test_cw_initial_roundtrip();
  test_cw_open_server_initial();
  test_cw_handshake_roundtrip();
  test_cw_wrong_direction_fails();
}
