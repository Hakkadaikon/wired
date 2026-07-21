#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvwire/wire.h"
#include "common/bytes/util/be.h"
#include "test.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/x25519.h"
#include "transport/packet/build/initpkt/initkeys.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/build/initpkt/initpkt.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/version/version/version.h"

/* @file
 * RFC 9368 Compatible Version Negotiation, server side: this SDK's
 * server never actively switches a connection's version -- it only ever
 * replies in whichever version the client's own Initial arrived in (RFC
 * 9368 2: no separate VN round trip when the arriving version is already
 * supported). These tests cover the receive-side and reply-side version
 * awareness that makes that true for QUIC v2 (RFC 9369) without changing
 * any v1 behavior. */

/* ---- quic_initpkt_derive_ver / quic_initpkt_open_ver ---- */

/* BASELINE: quic_initpkt_derive_ver(..., QUIC_VERSION_1, ...) must not
 * diverge from the plain (implicitly v1) quic_initpkt_derive -- the RFC
 * 9001 A.1 golden vector already pins quic_initpkt_derive in
 * initpkt_test.c, so equality with it is the v1 regression guard for the
 * new _ver entry point. */
static void test_derive_ver_v1_matches_default(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys ck1, sk1, ck2, sk2;
  quic_initpkt_derive(quic_span_of(dcid, 8), &ck1, &sk1);
  quic_initpkt_derive_ver(quic_span_of(dcid, 8), QUIC_VERSION_1, &ck2, &sk2);
  for (usz i = 0; i < 16; i++) CHECK(ck1.key[i] == ck2.key[i]);
  for (usz i = 0; i < 12; i++) CHECK(ck1.iv[i] == ck2.iv[i]);
  for (usz i = 0; i < 16; i++) CHECK(ck1.hp[i] == ck2.hp[i]);
}

/* v2 Initial keys differ from v1's (RFC 9369 3.3.1's distinct salt, already
 * golden-vector-pinned in v2keys_test.c) -- catches a copy-paste that wired
 * the v1 salt into the v2 path. */
static void test_derive_ver_v2_differs_from_v1(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys ck1, sk1, ck2, sk2;
  int               same_key = 1;
  quic_initpkt_derive_ver(quic_span_of(dcid, 8), QUIC_VERSION_1, &ck1, &sk1);
  quic_initpkt_derive_ver(quic_span_of(dcid, 8), QUIC_VERSION_2, &ck2, &sk2);
  for (usz i = 0; i < 16; i++)
    if (ck1.key[i] != ck2.key[i]) same_key = 0;
  CHECK(!same_key);
}

/* Round-trip proof for v2 (no independent golden AEAD vector is available
 * offline, per rfc-and-verification-layers.md): build a v2 Initial with
 * quic_initpkt_build_ver and open it with quic_initpkt_open_ver, the CRYPTO
 * payload must come back byte-for-byte. */
static void test_initpkt_ver_v2_roundtrip(void) {
  const u8          dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  const u8          scid[4] = {9, 9, 9, 9};
  const u8          ch[]    = {'v', '2', 'c', 'h'};
  u8                pkt[1300];
  quic_initpkt_desc d = {
      quic_span_of(dcid, 8), quic_span_of(scid, 4), quic_span_of(ch, 4), 0, 0};
  quic_obuf o = quic_obuf_of(pkt, sizeof(pkt));
  CHECK(quic_initpkt_build_ver(QUIC_VERSION_2, &d, &o));
  CHECK(o.len >= 1200);

  quic_span crypto;
  CHECK(quic_initpkt_open_ver(
      quic_span_of(dcid, 8), QUIC_VERSION_2, quic_mspan_of(pkt, o.len),
      &crypto));
  CHECK(crypto.p[0] == 0x06); /* CRYPTO frame type */
  for (usz i = 0; i < 4; i++) CHECK(crypto.p[3 + i] == ch[i]);
}

/* Opening a v2-built Initial as if it were v1 fails (AEAD authentication:
 * the derived keys differ) -- proves the version actually gates decryption
 * rather than being a cosmetic parameter. */
static void test_initpkt_ver_wrong_version_fails(void) {
  const u8          dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  const u8          ch[]    = {'x'};
  u8                pkt[1300];
  quic_initpkt_desc d = {
      quic_span_of(dcid, 8), quic_span_of((const u8*)0, 0), quic_span_of(ch, 1),
      0, 0};
  quic_obuf o = quic_obuf_of(pkt, sizeof(pkt));
  quic_span crypto;
  CHECK(quic_initpkt_build_ver(QUIC_VERSION_2, &d, &o));
  CHECK(!quic_initpkt_open_ver(
      quic_span_of(dcid, 8), QUIC_VERSION_1, quic_mspan_of(pkt, o.len),
      &crypto));
}

/* v2's Initial byte0 type bits differ from v1's (RFC 9369 3.2: wire value 1,
 * not 0) -- the built packet must wear them, not v1's. */
static void test_initpkt_ver_v2_byte0_type_bits(void) {
  const u8          dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  const u8          ch[]    = {'x'};
  u8                pkt[1300];
  quic_initpkt_desc d = {
      quic_span_of(dcid, 8), quic_span_of((const u8*)0, 0), quic_span_of(ch, 1),
      0, 0};
  quic_obuf o = quic_obuf_of(pkt, sizeof(pkt));
  CHECK(quic_initpkt_build_ver(QUIC_VERSION_2, &d, &o));
  CHECK(quic_packet_long_type(pkt[0], QUIC_VERSION_2) == QUIC_PT_INITIAL);
  /* the same byte read under v1's table must NOT decode as Initial (it is
   * v1's 0-RTT wire bits, RFC 9369 3.2's rotation) -- catches accidentally
   * reusing v1's byte0 for a v2 packet. */
  CHECK(quic_packet_long_type(pkt[0], QUIC_VERSION_1) != QUIC_PT_INITIAL);
}

/* ---- wired_srvboot_is_initial ---- */

/* BASELINE regression: a v1 Initial (byte0 0xc3-family) is still recognized.
 */
static void test_is_initial_v1_still_recognized(void) {
  u8 dg[1200] = {0};
  dg[0]       = 0xc3; /* long + fixed + Initial(00) + pnlen 4-1 */
  quic_put_be32(dg + 1, QUIC_VERSION_1);
  dg[5] = 0; /* zero-length DCID */
  CHECK(wired_srvboot_is_initial(dg, sizeof(dg)) == 1);
}

/* A v2 Initial's byte0 (type bits 01, RFC 9369 3.2) must now be recognized
 * too -- this exact byte0 value used to be mistaken for v1's 0-RTT (also
 * type bits 01) and rejected outright before this SDK read the version. */
static void test_is_initial_v2_recognized(void) {
  u8 dg[1200] = {0};
  dg[0]       = 0xd3; /* long + fixed + v2 Initial(01) + pnlen 4-1 */
  quic_put_be32(dg + 1, QUIC_VERSION_2);
  dg[5] = 0;
  CHECK(wired_srvboot_is_initial(dg, sizeof(dg)) == 1);
}

/* The very same byte0 (0xd3, wire type bits 01) under v1's table is 0-RTT,
 * not Initial -- must be rejected when the version field says v1. */
static void test_is_initial_v1_0rtt_bits_rejected(void) {
  u8 dg[1200] = {0};
  dg[0]       = 0xd3;
  quic_put_be32(dg + 1, QUIC_VERSION_1);
  dg[5] = 0;
  CHECK(wired_srvboot_is_initial(dg, sizeof(dg)) == 0);
}

/* ---- wired_srvboot_vneg ---- */

static u8 vneg_dg[1200];

static void vneg_dg_init(u32 unsupported_version) {
  for (usz i = 0; i < sizeof(vneg_dg); i++) vneg_dg[i] = 0;
  vneg_dg[0] = 0x80; /* long header, some unsupported version */
  quic_put_be32(vneg_dg + 1, unsupported_version);
  vneg_dg[5] = 0; /* DCID len 0 */
  vneg_dg[6] = 0; /* SCID len 0 */
}

/* The server's Version Negotiation packet must list BOTH versions it
 * accepts directly (v1 and v2, RFC 9368 5). */
static void test_vneg_lists_v1_and_v2(void) {
  u8  out[64];
  int saw_v1 = 0, saw_v2 = 0;
  vneg_dg_init(0x0a0a0a0au); /* a GREASE-shaped unsupported version */
  usz n = wired_srvboot_vneg(quic_span_of(vneg_dg, sizeof(vneg_dg)), out, 64);
  CHECK(n > 0);
  /* supported-version list starts right after the swapped-CID header
   * (byte0, 4-byte version=0, DCIDlen+DCID, SCIDlen+SCID); DCID/SCID here
   * are both empty so the list starts at offset 7. */
  for (usz off = 7; off + 4 <= n; off += 4) {
    u32 v = quic_get_be32(out + off);
    if (v == QUIC_VERSION_1) saw_v1 = 1;
    if (v == QUIC_VERSION_2) saw_v2 = 1;
  }
  CHECK(saw_v1 && saw_v2);
}

/* A v2 Initial must NOT trigger Version Negotiation any more -- v2 is now a
 * version this server speaks directly. */
static void test_vneg_not_owed_for_v2(void) {
  vneg_dg_init(QUIC_VERSION_2);
  u8  out[64];
  usz n = wired_srvboot_vneg(quic_span_of(vneg_dg, sizeof(vneg_dg)), out, 64);
  CHECK(n == 0);
}

/* A genuinely unsupported version still gets VN'd (regression: the VN gate
 * itself must not have been disabled by broadening the accept list). */
static void test_vneg_owed_for_alien_version(void) {
  vneg_dg_init(0x0a0a0a0au);
  u8  out[64];
  usz n = wired_srvboot_vneg(quic_span_of(vneg_dg, sizeof(vneg_dg)), out, 64);
  CHECK(n > 0);
}

/* ---- full accept path: a v2 Initial is accepted and replied to in v2 ---- */

struct sbv_fix {
  wired_server  s;
  wired_srvloop l;
};

/* A minimal but real ClientHello (x25519 key_share only, no transport
 * parameters payload beyond an empty TP list) -- enough for
 * wired_server_recv_initial to accept it and build a flight, mirroring
 * h3_loopback_test.c's lb_make_client_hello. */
static usz sbv_make_client_hello(u8* ch, usz cap) {
  static const u8 tp[1] = {0};
  u8              cli_priv[32], cli_pub[32], srv_random[32];
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  quic_obuf ob = quic_obuf_of(ch, cap);
  return quic_tls_client_hello(
      &(quic_clienthello_in){
          srv_random, cli_pub, quic_span_of(0, 0), quic_span_of(tp, 1)},
      &ob);
}

/* A v2-framed Initial carrying a real ClientHello is accepted by
 * wired_srvboot_accept, and the sealed reply is itself a v2-versioned
 * server Initial (RFC 9368 2: no VN round trip -- the server just answers
 * in the version that arrived). */
static void test_srvboot_accept_v2_initial(void) {
  struct sbv_fix f = {0};
  u8             ch[512];
  usz            ch_len      = sbv_make_client_hello(ch, sizeof(ch));
  const u8       dcid[8]     = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  const u8       cli_scid[4] = {0xaa, 0xbb, 0xcc, 0xdd};
  u8             srv_priv[32], srv_pub[32], cert_seed[32];
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_seed[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);

  u8                pkt[1300];
  quic_initpkt_desc d = {
      quic_span_of(dcid, 8), quic_span_of(cli_scid, 4),
      quic_span_of(ch, ch_len), 0, 0};
  quic_obuf o = quic_obuf_of(pkt, sizeof(pkt));
  CHECK(quic_initpkt_build_ver(QUIC_VERSION_2, &d, &o));

  wired_srvboot_id id = {0};
  id.priv             = srv_priv;
  id.pub              = srv_pub;
  id.cert_seed        = cert_seed;
  id.scid             = (const u8*)"SRVI";
  id.scid_len         = 4;
  id.random           = srv_priv; /* any 32 bytes; content unchecked here */

  u8                 init_buf[1500], flight_buf[4096];
  quic_obuf          init_ob   = quic_obuf_of(init_buf, sizeof(init_buf));
  quic_obuf          flight_ob = quic_obuf_of(flight_buf, sizeof(flight_buf));
  wired_srvboot_out  out       = {&init_ob, &flight_ob, {0}, 0, 0};
  wired_srvboot_conn conn      = {&f.s, &f.l};
  wired_srvboot_in   in        = {&id, quic_mspan_of(pkt, o.len)};

  CHECK(wired_srvboot_accept(&conn, &in, &out) == 1);
  /* the sealed server Initial's own long-header Version field must be v2,
   * not the old hardcoded v1 (bytes 1..4 after byte0). */
  CHECK(quic_get_be32(init_buf + 1) == QUIC_VERSION_2);
  CHECK(quic_packet_long_type(init_buf[0], QUIC_VERSION_2) == QUIC_PT_INITIAL);
}

void test_srvboot_version(void) {
  test_derive_ver_v1_matches_default();
  test_derive_ver_v2_differs_from_v1();
  test_initpkt_ver_v2_roundtrip();
  test_initpkt_ver_wrong_version_fails();
  test_initpkt_ver_v2_byte0_type_bits();
  test_is_initial_v1_still_recognized();
  test_is_initial_v2_recognized();
  test_is_initial_v1_0rtt_bits_rejected();
  test_vneg_lists_v1_and_v2();
  test_vneg_not_owed_for_v2();
  test_vneg_owed_for_alien_version();
  test_srvboot_accept_v2_initial();
}
