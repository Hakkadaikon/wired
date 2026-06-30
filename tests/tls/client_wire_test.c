#include "tls/handshake/roles/client/clientwire.h"
#include "initpkt/initopen.h"
#include "tls/keys/schedule_drive/keyschedule.h"
#include "app/http3/server/srvwire/wire.h"
#include "test.h"
#include "tls/handshake/core/tls/x25519.h"

/* RFC 9001 4 / 5, WireHS: the client real-wire path seals with its own
 * direction (CLIENT_*) and opens with the peer direction (SERVER_*). */

static const u8 cw_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
static const u8 cw_scid[4] = {0x11, 0x22, 0x33, 0x44};

/* Drive a fresh keysched to the master stage so all four directional keys
 * (CLIENT_HS/SERVER_HS/CLIENT_AP/SERVER_AP) are derived, then plant it in c. */
static void cw_derive_keys(quic_client *c)
{
    u8 ecdhe[32], tr[] = "ClientHello||ServerHello";
    for (usz i = 0; i < 32; i++)
        ecdhe[i] = (u8)(1 + i);
    quic_keysched_init(&c->tls.ks);
    CHECK(quic_keysched_advance_handshake(&c->tls.ks, ecdhe, 32, tr, sizeof(tr)) == 1);
    CHECK(quic_keysched_advance_master(&c->tls.ks, tr, sizeof(tr)) == 1);
}

/* RFC 9001 5.2: client seals its real ClientHello into a protected Initial.
 * The peer opens it with the (client-direction) Initial keys derived from the
 * same DCID and recovers a CRYPTO frame carrying the ClientHello (type 0x01). */
static void test_cw_initial_roundtrip(void)
{
    quic_client c;
    u8 priv[32], pub[32], pkt[1300];
    usz total = 0, clen = 0;
    const u8 *frames = 0;
    for (usz i = 0; i < 32; i++)
        priv[i] = (u8)(7 + i);
    quic_x25519_base(pub, priv);
    quic_tlsdriver_init(&c.tls, priv, pub, 0);
    CHECK(quic_client_build_initial_wire(&c, cw_dcid, 8, cw_scid, 4, 0,
                                         pkt, sizeof(pkt), &total) == 1);
    CHECK(total == 1200);
    CHECK(quic_initpkt_open(cw_dcid, 8, pkt, total, 0, &frames, &clen) == 1);
    CHECK(frames[0] == 0x06);          /* CRYPTO frame */
    CHECK(frames[1] == 0x00);          /* offset 0 */
    CHECK((frames[2] & 0xc0) == 0x40); /* 2-byte length varint */
    CHECK(frames[4] == 0x01);          /* ClientHello after the header */
    (void)clen;
}

/* RFC 9001 5.2: client opens a server Initial sealed by the server codec. */
static void test_cw_open_server_initial(void)
{
    const u8 sh[] = {0x02, 0x00, 0x00, 0x02, 0xab, 0xcd};
    u8 pkt[1300];
    usz total = 0, tls_len = 0;
    const u8 *tls = 0;
    CHECK(quic_srvwire_seal_initial(cw_dcid, 8, cw_scid, 4, 0, -1, sh, sizeof(sh),
                                    pkt, sizeof(pkt), &total) == 1);
    CHECK(quic_client_open_initial_wire(cw_dcid, 8, pkt, total, 0,
                                        &tls, &tls_len) == 1);
    CHECK(tls_len == sizeof(sh));
    for (usz i = 0; i < sizeof(sh); i++)
        CHECK(tls[i] == sh[i]);
}

/* RFC 9001 5: client seals a Handshake flight with CLIENT_HS; the peer opens it
 * with the client-direction key. Then client opens a SERVER_HS-sealed flight. */
static void test_cw_handshake_roundtrip(void)
{
    quic_client c;
    const u8 fin[] = {0x14, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03};
    u8 pkt[512];
    usz total = 0, tls_len = 0;
    const u8 *tls = 0;
    const quic_initial_keys *chs, *shs;
    quic_aes128 hp;
    cw_derive_keys(&c);

    /* client seals with CLIENT_HS; peer opens with the same client key. */
    CHECK(quic_client_seal_handshake_wire(&c, cw_dcid, 8, cw_scid, 4, 0,
                                          fin, sizeof(fin),
                                          pkt, sizeof(pkt), &total) == 1);
    CHECK(quic_keysched_get(&c.tls.ks, QUIC_KS_CLIENT_HS, &chs) == 1);
    quic_aes128_init(&hp, chs->hp);
    CHECK(quic_srvwire_open_handshake(chs, &hp, pkt, total, 8,
                                      &tls, &tls_len) == 1);
    CHECK(tls_len == sizeof(fin));

    /* client opens a flight sealed with SERVER_HS (peer direction). */
    CHECK(quic_keysched_get(&c.tls.ks, QUIC_KS_SERVER_HS, &shs) == 1);
    quic_aes128_init(&hp, shs->hp);
    CHECK(quic_srvwire_seal_handshake(shs, &hp, cw_dcid, 8, cw_scid, 4, 0, -1,
                                      fin, sizeof(fin), pkt, sizeof(pkt),
                                      &total) == 1);
    CHECK(quic_client_open_handshake_wire(&c, pkt, total, 8,
                                          &tls, &tls_len) == 1);
    CHECK(tls_len == sizeof(fin));
    for (usz i = 0; i < sizeof(fin); i++)
        CHECK(tls[i] == fin[i]);
}

/* WireHS negative: a client-sealed (CLIENT_HS) Handshake packet must NOT open
 * with the client's own open key (SERVER_HS); wrong direction fails AEAD. */
static void test_cw_wrong_direction_fails(void)
{
    quic_client c;
    const u8 fin[] = {0x14, 0x00, 0x00, 0x01, 0x09};
    u8 pkt[512];
    usz total = 0, tls_len = 0;
    const u8 *tls = 0;
    cw_derive_keys(&c);
    CHECK(quic_client_seal_handshake_wire(&c, cw_dcid, 8, cw_scid, 4, 0,
                                          fin, sizeof(fin),
                                          pkt, sizeof(pkt), &total) == 1);
    /* opening own-sealed packet with the peer-direction open key must fail. */
    CHECK(quic_client_open_handshake_wire(&c, pkt, total, 8,
                                          &tls, &tls_len) == 0);
}

/* RFC 9001 5: client sends 1-RTT with CLIENT_AP; receiving 200 opens with
 * SERVER_AP. Round-trip each direction with the matching key. */
static void test_cw_onertt_roundtrip(void)
{
    quic_client c;
    const u8 get[] = {'G', 'E', 'T'};
    const u8 ok[] = {'2', '0', '0'};
    u8 pkt[256];
    usz total = 0, dlen = 0;
    u64 sid = 0, off = 9;
    const u8 *data = 0;
    int fin = 0;
    const quic_initial_keys *cap, *sap;
    quic_aes128 hp;
    cw_derive_keys(&c);

    /* client GET sealed with CLIENT_AP; peer opens with the same client key. */
    CHECK(quic_client_send_appdata_wire(&c, cw_dcid, 8, 0, 4, get, sizeof(get),
                                        0, pkt, sizeof(pkt), &total) == 1);
    CHECK(quic_keysched_get(&c.tls.ks, QUIC_KS_CLIENT_AP, &cap) == 1);
    quic_aes128_init(&hp, cap->hp);
    CHECK(quic_appdata_recv(cap, &hp, pkt, total, 8, &sid, &off,
                            &data, &dlen, &fin) == 1);
    CHECK(sid == 4 && dlen == sizeof(get));

    /* server 200 sealed with SERVER_AP; its DCID is the client's SCID (RFC 9000
     * 5.1), so the client opens it with SERVER_AP and accepts the DCID. */
    CHECK(quic_keysched_get(&c.tls.ks, QUIC_KS_SERVER_AP, &sap) == 1);
    quic_aes128_init(&hp, sap->hp);
    CHECK(quic_appdata_send(sap, &hp, cw_scid, 4, 0, 0, ok, sizeof(ok), 1,
                            pkt, sizeof(pkt), &total) == 1);
    CHECK(quic_client_recv_appdata_wire(&c, pkt, total, cw_scid, 4, &sid, &off,
                                        &data, &dlen, &fin) == 1);
    CHECK(dlen == sizeof(ok) && fin == 1);
    for (usz i = 0; i < sizeof(ok); i++)
        CHECK(data[i] == ok[i]);
}

/* RFC 9000 5.1 (#28): a server reply whose DCID is NOT the client's SCID (the
 * mix-up bug — the server echoed some other id) is dropped before the AEAD even
 * runs, so a misrouted reply cannot be mistaken for ours. This is the check curl
 * applies; wiring it into the in-tree client surfaces the mix-up in tests. */
static void test_cw_onertt_wrong_dcid_dropped(void)
{
    quic_client c;
    const u8 ok[] = {'2', '0', '0'};
    const u8 not_ours[4] = {0xaa, 0xbb, 0xcc, 0xdd};
    u8 pkt[256];
    usz total = 0, dlen = 0;
    u64 sid = 0, off = 0;
    const u8 *data = 0;
    int fin = 0;
    const quic_initial_keys *sap;
    quic_aes128 hp;
    cw_derive_keys(&c);
    CHECK(quic_keysched_get(&c.tls.ks, QUIC_KS_SERVER_AP, &sap) == 1);
    quic_aes128_init(&hp, sap->hp);
    /* a validly sealed 200, but addressed to a DCID that is not our SCID. */
    CHECK(quic_appdata_send(sap, &hp, not_ours, 4, 0, 0, ok, sizeof(ok), 1,
                            pkt, sizeof(pkt), &total) == 1);
    CHECK(quic_client_recv_appdata_wire(&c, pkt, total, cw_scid, 4, &sid, &off,
                                        &data, &dlen, &fin) == 0);
}

void test_client_wire(void)
{
    test_cw_initial_roundtrip();
    test_cw_open_server_initial();
    test_cw_handshake_roundtrip();
    test_cw_wrong_direction_fails();
    test_cw_onertt_roundtrip();
    test_cw_onertt_wrong_dcid_dropped();
}
