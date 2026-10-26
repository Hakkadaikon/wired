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
 * RFC 9368 Compatible Version Negotiation, server side: the server
 * replies in the client Initial's own version by default, and switches
 * its whole first flight to the most preferred mutually supported
 * version when the ClientHello's version_information transport
 * parameter offers one (RFC 9368 2.3: the switch happens inside the
 * server's first flight, no separate VN round trip). These tests cover
 * the receive-side and reply-side version awareness for QUIC v2 (RFC
 * 9369) without changing any v1 behavior. */

/* ---- initpkt_derive_ver / initpkt_open_ver ---- */

/* BASELINE: initpkt_derive_ver(..., VERSION_1, ...) must not
 * diverge from the plain (implicitly v1) initpkt_derive -- the RFC
 * 9001 A.1 golden vector already pins initpkt_derive in
 * initpkt_test.c, so equality with it is the v1 regression guard for the
 * new _ver entry point. */
static void test_derive_ver_v1_matches_default(void) {
  const u8     dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  initial_keys ck1, sk1, ck2, sk2;
  initpkt_derive(wired_span_of(dcid, 8), &ck1, &sk1);
  initpkt_derive_ver(wired_span_of(dcid, 8), VERSION_1, &ck2, &sk2);
  for (usz i = 0; i < 16; i++) {
    CHECK(ck1.key[i] == ck2.key[i]);
  }
  for (usz i = 0; i < 12; i++) {
    CHECK(ck1.iv[i] == ck2.iv[i]);
  }
  for (usz i = 0; i < 16; i++) {
    CHECK(ck1.hp[i] == ck2.hp[i]);
  }
}

/* v2 Initial keys differ from v1's (RFC 9369 3.3.1's distinct salt, already
 * golden-vector-pinned in v2keys_test.c) -- catches a copy-paste that wired
 * the v1 salt into the v2 path. */
static void test_derive_ver_v2_differs_from_v1(void) {
  const u8     dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  initial_keys ck1, sk1, ck2, sk2;
  int          same_key = 1;
  initpkt_derive_ver(wired_span_of(dcid, 8), VERSION_1, &ck1, &sk1);
  initpkt_derive_ver(wired_span_of(dcid, 8), VERSION_2, &ck2, &sk2);
  for (usz i = 0; i < 16; i++) {
    if (ck1.key[i] != ck2.key[i]) {
      same_key = 0;
    }
  }
  CHECK(!same_key);
}

/* Round-trip proof for v2 (no independent golden AEAD vector is available
 * offline, per rfc-and-verification-layers.md): build a v2 Initial with
 * initpkt_build_ver and open it with initpkt_open_ver, the CRYPTO
 * payload must come back byte-for-byte. */
static void test_initpkt_ver_v2_roundtrip(void) {
  const u8     dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  const u8     scid[4] = {9, 9, 9, 9};
  const u8     ch[]    = {'v', '2', 'c', 'h'};
  u8           pkt[1300];
  initpkt_desc d = {
      wired_span_of(dcid, 8), wired_span_of(scid, 4), wired_span_of(ch, 4), 0,
      0};
  wired_obuf o = obuf_of(pkt, sizeof(pkt));
  CHECK(initpkt_build_ver(VERSION_2, &d, &o));
  CHECK(o.len >= 1200);

  wired_span crypto;
  CHECK(initpkt_open_ver(
      wired_span_of(dcid, 8), VERSION_2, wired_mspan_of(pkt, o.len), 0,
      &crypto));
  CHECK(crypto.p[0] == 0x06); /* CRYPTO frame type */
  for (usz i = 0; i < 4; i++) {
    CHECK(crypto.p[3 + i] == ch[i]);
  }
}

/* Opening a v2-built Initial as if it were v1 fails (AEAD authentication:
 * the derived keys differ) -- proves the version actually gates decryption
 * rather than being a cosmetic parameter. */
static void test_initpkt_ver_wrong_version_fails(void) {
  const u8     dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  const u8     ch[]    = {'x'};
  u8           pkt[1300];
  initpkt_desc d = {
      wired_span_of(dcid, 8), wired_span_of((const u8*)0, 0),
      wired_span_of(ch, 1), 0, 0};
  wired_obuf o = obuf_of(pkt, sizeof(pkt));
  wired_span crypto;
  CHECK(initpkt_build_ver(VERSION_2, &d, &o));
  CHECK(!initpkt_open_ver(
      wired_span_of(dcid, 8), VERSION_1, wired_mspan_of(pkt, o.len), 0,
      &crypto));
}

/* v2's Initial byte0 type bits differ from v1's (RFC 9369 3.2: wire value 1,
 * not 0) -- the built packet must wear them, not v1's. */
static void test_initpkt_ver_v2_byte0_type_bits(void) {
  const u8     dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  const u8     ch[]    = {'x'};
  u8           pkt[1300];
  initpkt_desc d = {
      wired_span_of(dcid, 8), wired_span_of((const u8*)0, 0),
      wired_span_of(ch, 1), 0, 0};
  wired_obuf o = obuf_of(pkt, sizeof(pkt));
  CHECK(initpkt_build_ver(VERSION_2, &d, &o));
  CHECK(packet_long_type(pkt[0], VERSION_2) == PT_INITIAL);
  /* the same byte read under v1's table must NOT decode as Initial (it is
   * v1's 0-RTT wire bits, RFC 9369 3.2's rotation) -- catches accidentally
   * reusing v1's byte0 for a v2 packet. */
  CHECK(packet_long_type(pkt[0], VERSION_1) != PT_INITIAL);
}

/* ---- wired_srvboot_is_initial ---- */

/* BASELINE regression: a v1 Initial (byte0 0xc3-family) is still recognized.
 */
static void test_is_initial_v1_still_recognized(void) {
  u8 dg[1200] = {0};
  dg[0]       = 0xc3; /* long + fixed + Initial(00) + pnlen 4-1 */
  be_put_be32(dg + 1, VERSION_1);
  dg[5] = 0; /* zero-length DCID */
  CHECK(wired_srvboot_is_initial(dg, sizeof(dg)) == 1);
}

/* A v2 Initial's byte0 (type bits 01, RFC 9369 3.2) must now be recognized
 * too -- this exact byte0 value used to be mistaken for v1's 0-RTT (also
 * type bits 01) and rejected outright before this SDK read the version. */
static void test_is_initial_v2_recognized(void) {
  u8 dg[1200] = {0};
  dg[0]       = 0xd3; /* long + fixed + v2 Initial(01) + pnlen 4-1 */
  be_put_be32(dg + 1, VERSION_2);
  dg[5] = 0;
  CHECK(wired_srvboot_is_initial(dg, sizeof(dg)) == 1);
}

/* The very same byte0 (0xd3, wire type bits 01) under v1's table is 0-RTT,
 * not Initial -- must be rejected when the version field says v1. */
static void test_is_initial_v1_0rtt_bits_rejected(void) {
  u8 dg[1200] = {0};
  dg[0]       = 0xd3;
  be_put_be32(dg + 1, VERSION_1);
  dg[5] = 0;
  CHECK(wired_srvboot_is_initial(dg, sizeof(dg)) == 0);
}

/* ---- wired_srvboot_vneg ---- */

static u8 vneg_dg[1200];

static void vneg_dg_init(u32 unsupported_version) {
  for (usz i = 0; i < sizeof(vneg_dg); i++) {
    vneg_dg[i] = 0;
  }
  vneg_dg[0] = 0x80; /* long header, some unsupported version */
  be_put_be32(vneg_dg + 1, unsupported_version);
  vneg_dg[5] = 0; /* DCID len 0 */
  vneg_dg[6] = 0; /* SCID len 0 */
}

/* The server's Version Negotiation packet must list BOTH versions it
 * accepts directly (v1 and v2, RFC 9368 5). */
static void test_vneg_lists_v1_and_v2(void) {
  u8  out[64];
  int saw_v1 = 0, saw_v2 = 0;
  vneg_dg_init(0x0a0a0a0au); /* a GREASE-shaped unsupported version */
  usz n =
      wired_srvboot_vneg(wired_span_of(vneg_dg, sizeof(vneg_dg)), 0, out, 64);
  CHECK(n > 0);
  /* supported-version list starts right after the swapped-CID header
   * (byte0, 4-byte version=0, DCIDlen+DCID, SCIDlen+SCID); DCID/SCID here
   * are both empty so the list starts at offset 7. */
  for (usz off = 7; off + 4 <= n; off += 4) {
    u32 v = be_get_be32(out + off);
    if (v == VERSION_1) {
      saw_v1 = 1;
    }
    if (v == VERSION_2) {
      saw_v2 = 1;
    }
  }
  CHECK(saw_v1 && saw_v2);
}

/* A v2 Initial must NOT trigger Version Negotiation any more -- v2 is now a
 * version this server speaks directly. */
static void test_vneg_not_owed_for_v2(void) {
  vneg_dg_init(VERSION_2);
  u8  out[64];
  usz n =
      wired_srvboot_vneg(wired_span_of(vneg_dg, sizeof(vneg_dg)), 0, out, 64);
  CHECK(n == 0);
}

/* A genuinely unsupported version still gets VN'd (regression: the VN gate
 * itself must not have been disabled by broadening the accept list). */
static void test_vneg_owed_for_alien_version(void) {
  vneg_dg_init(0x0a0a0a0au);
  u8  out[64];
  usz n =
      wired_srvboot_vneg(wired_span_of(vneg_dg, sizeof(vneg_dg)), 0, out, 64);
  CHECK(n > 0);
}

/* RFC 9308 13: the application's WIRED_VERSIONS_* mask narrows what the
 * server accepts -- with only v1 accepted a v2 Initial draws Version
 * Negotiation listing v1 alone, and with only v2 accepted so does a v1
 * Initial (listing v2 alone). */
static void test_vneg_honors_version_mask(void) {
  u8  out[64];
  usz n;
  vneg_dg_init(VERSION_2);
  n = wired_srvboot_vneg(
      wired_span_of(vneg_dg, sizeof(vneg_dg)), WIRED_VERSIONS_V1, out, 64);
  CHECK(n == 7 + 4);
  CHECK(be_get_be32(out + 7) == VERSION_1);
  vneg_dg_init(VERSION_1);
  n = wired_srvboot_vneg(
      wired_span_of(vneg_dg, sizeof(vneg_dg)), WIRED_VERSIONS_V2, out, 64);
  CHECK(n == 7 + 4);
  CHECK(be_get_be32(out + 7) == VERSION_2);
  n = wired_srvboot_vneg(
      wired_span_of(vneg_dg, sizeof(vneg_dg)), WIRED_VERSIONS_V1, out, 64);
  CHECK(n == 0); /* v1 accepted: no Version Negotiation owed */
}

/* ---- full accept path: a v2 Initial is accepted and replied to in v2 ---- */

struct sbv_fix {
  wired_server  s;
  wired_srvloop l;
};

/* Too big for the stack of a test that boots several times. */
static struct sbv_fix g_sbv_fix;
/* wired_srvboot_id.idle_timeout_ms for sbv_boot_ch (0 = default). */
static u64 g_sbv_idle_ms;

/* A minimal but real ClientHello (x25519 key_share only) whose transport
 * parameter list is exactly `tp` -- enough for wired_server_recv_initial
 * to accept it and build a flight, mirroring h3_loopback_test.c's
 * lb_make_client_hello. */
static usz sbv_make_client_hello_tp(u8* ch, usz cap, wired_span tp) {
  /* RFC 9000 7.3: every fixture Initial's SCID (cli_scid below). */
  static const u8 cli_scid[4] = {0xaa, 0xbb, 0xcc, 0xdd};
  u8              cli_priv[32], cli_pub[32], srv_random[32], all[96];
  wired_obuf      tob = obuf_of(all + tp.n, sizeof all - tp.n);
  CHECK(tp.n <= 64);
  bytes_memcpy(all, tp.p, tp.n);
  tp = wired_span_of(
      all, tp.n + tparam_put_blob(
                      &tob, TP_INITIAL_SOURCE_CONNECTION_ID,
                      wired_span_of(cli_scid, 4)));
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  wired_x25519_base(cli_pub, cli_priv);
  wired_obuf ob = obuf_of(ch, cap);
  return tls_client_hello(
      &(clienthello_in){srv_random, cli_pub, wired_span_of(0, 0), tp}, &ob);
}

static usz sbv_make_client_hello(u8* ch, usz cap) {
  return sbv_make_client_hello_tp(ch, cap, wired_span_of(0, 0));
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
  wired_x25519_base(srv_pub, srv_priv);

  u8           pkt[1300];
  initpkt_desc d = {
      wired_span_of(dcid, 8), wired_span_of(cli_scid, 4),
      wired_span_of(ch, ch_len), 0, 0};
  wired_obuf o = obuf_of(pkt, sizeof(pkt));
  CHECK(initpkt_build_ver(VERSION_2, &d, &o));

  wired_srvboot_id id = {0};
  id.priv             = srv_priv;
  id.pub              = srv_pub;
  id.cert_seed        = cert_seed;
  id.scid             = (const u8*)"SRVI";
  id.scid_len         = 4;
  id.random           = srv_priv; /* any 32 bytes; content unchecked here */

  u8                 init_buf[1500], flight_buf[4096];
  wired_obuf         init_ob   = obuf_of(init_buf, sizeof(init_buf));
  wired_obuf         flight_ob = obuf_of(flight_buf, sizeof(flight_buf));
  wired_srvboot_out  out       = {&init_ob, &flight_ob, {0}, 0, 0};
  wired_srvboot_conn conn      = {&f.s, &f.l};
  wired_srvboot_in   in        = {&id, wired_mspan_of(pkt, o.len)};

  CHECK(wired_srvboot_accept(&conn, &in, &out) == 1);
  /* the sealed server Initial's own long-header Version field must be v2,
   * not the old hardcoded v1 (bytes 1..4 after byte0). */
  CHECK(be_get_be32(init_buf + 1) == VERSION_2);
  CHECK(packet_long_type(init_buf[0], VERSION_2) == PT_INITIAL);
}

/* Boot the server from a v1 Initial sealed with header SCID hdr_scid around
 * the ClientHello ch; returns wired_srvboot_accept's verdict. */
static int sbv_boot_ch(struct sbv_fix* f, wired_span ch, wired_span hdr_scid) {
  static const u8 dcid[8] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
  u8              srv_priv[32], srv_pub[32], cert_seed[32], pkt[1300];
  u8              init_buf[1500], flight_buf[4096];
  initpkt_desc    d = {wired_span_of(dcid, 8), hdr_scid, ch, 0, 0};
  wired_obuf      o = obuf_of(pkt, sizeof(pkt));
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_seed[i] = (u8)(0x80 + i);
  }
  wired_x25519_base(srv_pub, srv_priv);
  CHECK(initpkt_build(&d, &o));
  wired_srvboot_id id          = {0};
  id.priv                      = srv_priv;
  id.pub                       = srv_pub;
  id.cert_seed                 = cert_seed;
  id.scid                      = (const u8*)"SRVI";
  id.scid_len                  = 4;
  id.random                    = srv_priv;
  id.idle_timeout_ms           = g_sbv_idle_ms;
  wired_obuf         init_ob   = obuf_of(init_buf, sizeof(init_buf));
  wired_obuf         flight_ob = obuf_of(flight_buf, sizeof(flight_buf));
  wired_srvboot_out  out       = {&init_ob, &flight_ob, {0}, 0, 0};
  wired_srvboot_conn conn      = {&f->s, &f->l};
  wired_srvboot_in   in        = {&id, wired_mspan_of(pkt, o.len)};
  return wired_srvboot_accept(&conn, &in, &out);
}

/* RFC 9000 7.3: initial_source_connection_id must be present and equal the
 * Initial's Source CID; either failure is a TRANSPORT_PARAMETER_ERROR. */
static void test_srvboot_iscid_validated(void) {
  static const u8 good[4] = {0xaa, 0xbb, 0xcc, 0xdd};
  static const u8 bad[4]  = {0xaa, 0xbb, 0xcc, 0xde};
  u8              ch[512], cli_pub[32], rnd[32] = {0};
  usz             n = sbv_make_client_hello(ch, sizeof(ch));
  struct sbv_fix* f = &g_sbv_fix;
  bytes_memset(f, 0, sizeof *f);
  CHECK(sbv_boot_ch(f, wired_span_of(ch, n), wired_span_of(good, 4)) == 1);
  bytes_memset(f, 0, sizeof *f);
  CHECK(sbv_boot_ch(f, wired_span_of(ch, n), wired_span_of(bad, 4)) == 0);
  CHECK(sdrv_last_error(&f->s.sdrv) == ERR_TRANSPORT_PARAMETER_ERROR);
  /* absent: a ClientHello with no transport parameters at all inside */
  wired_x25519_base(cli_pub, rnd);
  n = tls_client_hello(
      &(clienthello_in){rnd, cli_pub, wired_span_of(0, 0), wired_span_of(0, 0)},
      &(wired_obuf){ch, sizeof ch, 0});
  bytes_memset(f, 0, sizeof *f);
  CHECK(sbv_boot_ch(f, wired_span_of(ch, n), wired_span_of(good, 4)) == 0);
  CHECK(sdrv_last_error(&f->s.sdrv) == ERR_TRANSPORT_PARAMETER_ERROR);
}

/* RFC 9000 18.2: an out-of-range (or server-only) client transport
 * parameter refuses the connection with TRANSPORT_PARAMETER_ERROR; the
 * boundary value boots. */
static void sbv_check_range(u64 id, u64 value, int want) {
  static const u8 scid[4] = {0xaa, 0xbb, 0xcc, 0xdd};
  u8              tp[16], ch[512];
  wired_obuf      tob = obuf_of(tp, sizeof tp);
  usz             tn  = tparam_put_int(&tob, id, value);
  usz n = sbv_make_client_hello_tp(ch, sizeof(ch), wired_span_of(tp, tn));
  bytes_memset(&g_sbv_fix, 0, sizeof g_sbv_fix);
  CHECK(
      sbv_boot_ch(&g_sbv_fix, wired_span_of(ch, n), wired_span_of(scid, 4)) ==
      want);
  if (!want) {
    CHECK(sdrv_last_error(&g_sbv_fix.s.sdrv) == ERR_TRANSPORT_PARAMETER_ERROR);
  }
}

/* Boot with the server's idle_timeout_ms = ours and a ClientHello whose
 * max_idle_timeout is peer (0 = absent); return the negotiated value. */
static u64 sbv_idle_negotiated(u64 ours, u64 peer) {
  static const u8 scid[4] = {0xaa, 0xbb, 0xcc, 0xdd};
  u8              tp[16], ch[512];
  wired_obuf      tob = obuf_of(tp, sizeof tp);
  usz tn = peer ? tparam_put_int(&tob, TP_MAX_IDLE_TIMEOUT, peer) : 0;
  usz n  = sbv_make_client_hello_tp(ch, sizeof(ch), wired_span_of(tp, tn));
  bytes_memset(&g_sbv_fix, 0, sizeof g_sbv_fix);
  g_sbv_idle_ms = ours;
  CHECK(
      sbv_boot_ch(&g_sbv_fix, wired_span_of(ch, n), wired_span_of(scid, 4)) ==
      1);
  g_sbv_idle_ms = 0;
  return wired_server_idle_timeout_ms(&g_sbv_fix.s);
}

/* RFC 9000 10.1 / RFC 9308 10: the app-set idle timeout and the client's
 * max_idle_timeout negotiate to their minimum; an absent one imposes no
 * limit, and an unset server value is the 30 s default. */
static void test_srvboot_idle_timeout_negotiated(void) {
  CHECK(sbv_idle_negotiated(7000, 9000) == 7000);
  CHECK(sbv_idle_negotiated(7000, 4000) == 4000);
  CHECK(sbv_idle_negotiated(7000, 0) == 7000);
  CHECK(sbv_idle_negotiated(0, 0) == 30000);
  CHECK(sbv_idle_negotiated(0, 60000) == 30000);
}

static void test_srvboot_tp_ranges_validated(void) {
  sbv_check_range(TP_MAX_UDP_PAYLOAD_SIZE, 1199, 0);
  sbv_check_range(TP_MAX_UDP_PAYLOAD_SIZE, 1200, 1);
  sbv_check_range(TP_ACK_DELAY_EXPONENT, 21, 0);
  sbv_check_range(TP_ACK_DELAY_EXPONENT, 20, 1);
  sbv_check_range(TP_MAX_ACK_DELAY, 16384, 0);
  sbv_check_range(TP_MAX_ACK_DELAY, 16383, 1);
  sbv_check_range(TP_ACTIVE_CONNECTION_ID_LIMIT, 1, 0);
  sbv_check_range(TP_ACTIVE_CONNECTION_ID_LIMIT, 2, 1);
  /* RFC 9000 4.6: max_streams above 2^60 is TRANSPORT_PARAMETER_ERROR */
  sbv_check_range(TP_INITIAL_MAX_STREAMS_BIDI, (1ull << 60) + 1, 0);
  sbv_check_range(TP_INITIAL_MAX_STREAMS_BIDI, 1ull << 60, 1);
  sbv_check_range(TP_INITIAL_MAX_STREAMS_UNI, (1ull << 60) + 1, 0);
  sbv_check_range(TP_INITIAL_MAX_STREAMS_UNI, 1ull << 60, 1);
  /* RFC 9000 7.4.2 / 18.1: an unknown, reserved (31*N+27) id is ignored */
  sbv_check_range(31 * 5 + 27, 7, 1);
  /* RFC 9000 18.2: a server-only parameter from the client */
  sbv_check_range(TP_ORIGINAL_DESTINATION_CONNECTION_ID, 5, 0);
}

/* RFC 9368 2.3: a v1 Initial whose ClientHello carries a
 * version_information transport parameter offering v2 makes the server
 * switch its whole first flight to v2 -- the sealed server Initial's own
 * Version field reads v2 (the interop "v2" testcase's exact check:
 * "Wrong version in server Initial. Expected 0x6b3343cf"). */
static void test_srvboot_v1_initial_with_vi_switches_to_v2(void) {
  struct sbv_fix f = {0};
  u8             ch[512], tp[64];
  version_info   vi          = {VERSION_1, 2, {VERSION_2, VERSION_1}};
  usz            tp_len      = version_info_encode(tp, sizeof(tp), &vi);
  const u8       dcid[8]     = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28};
  const u8       cli_scid[4] = {0xaa, 0xbb, 0xcc, 0xdd};
  u8             srv_priv[32], srv_pub[32], cert_seed[32];
  usz            ch_len;
  CHECK(tp_len != 0);
  ch_len = sbv_make_client_hello_tp(ch, sizeof(ch), wired_span_of(tp, tp_len));
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_seed[i] = (u8)(0x80 + i);
  }
  wired_x25519_base(srv_pub, srv_priv);

  u8           pkt[1300];
  initpkt_desc d = {
      wired_span_of(dcid, 8), wired_span_of(cli_scid, 4),
      wired_span_of(ch, ch_len), 0, 0};
  wired_obuf o = obuf_of(pkt, sizeof(pkt));
  CHECK(initpkt_build(&d, &o)); /* the client's Initial itself stays v1 */

  wired_srvboot_id id = {0};
  id.priv             = srv_priv;
  id.pub              = srv_pub;
  id.cert_seed        = cert_seed;
  id.scid             = (const u8*)"SRVI";
  id.scid_len         = 4;
  id.random           = srv_priv; /* any 32 bytes; content unchecked here */

  u8                 init_buf[1500], flight_buf[4096];
  wired_obuf         init_ob   = obuf_of(init_buf, sizeof(init_buf));
  wired_obuf         flight_ob = obuf_of(flight_buf, sizeof(flight_buf));
  wired_srvboot_out  out       = {&init_ob, &flight_ob, {0}, 0, 0};
  wired_srvboot_conn conn      = {&f.s, &f.l};
  wired_srvboot_in   in        = {&id, wired_mspan_of(pkt, o.len)};

  CHECK(wired_srvboot_accept(&conn, &in, &out) == 1);
  /* the whole flight switched: the server Initial's Version field is v2 */
  CHECK(be_get_be32(init_buf + 1) == VERSION_2);
  CHECK(packet_long_type(init_buf[0], VERSION_2) == PT_INITIAL);

  /* RFC 9308 13: the same Initial to a server the application restricted
   * to v1 is answered in v1 -- compatible negotiation never picks a
   * version outside the accepted set. */
  f           = (struct sbv_fix){0};
  init_ob     = obuf_of(init_buf, sizeof(init_buf));
  flight_ob   = obuf_of(flight_buf, sizeof(flight_buf));
  out         = (wired_srvboot_out){&init_ob, &flight_ob, {0}, 0, 0};
  id.versions = WIRED_VERSIONS_V1;
  o           = obuf_of(pkt, sizeof(pkt));
  CHECK(initpkt_build(&d, &o));
  in = (wired_srvboot_in){&id, wired_mspan_of(pkt, o.len)};
  CHECK(wired_srvboot_accept(&conn, &in, &out) == 1);
  CHECK(be_get_be32(init_buf + 1) == VERSION_1);
  CHECK(sdrv_wire_version(&f.s.sdrv) == VERSION_1);
}

/* Pinned to a captured neqo v2 interop run (compatible upgrade, split
 * ClientHello): the server ACKed the partial ClientHello at Initial pn 2
 * in v1, then sent the accept flight's Initial at pn 1 -- neqo, treating
 * the Initial pn space as continuous across the switch (RFC 9368 2.3
 * keeps the connection), dropped every flight retransmission with "too
 * old packet number: 1 < 3" and idled out. Once a partial ack spent pn 2,
 * the flight must take the next unused pn, not fall back to 1. */
static void test_srvboot_flight_pn_continues_past_partial_ack(void) {
  wired_srvboot_acc a       = {0};
  u8                scid[6] = {0x06, 0xed, 0x67, 0xd0, 0x9b, 0x22};
  u8                out[288];
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_flight_pn(&a) == 1); /* nothing sent yet: pn 1 */
  wired_srvboot_acc_reset(&a);
  a.any          = 1;
  a.opened       = 1;
  a.largest_pn   = 20;
  a.hdr.version  = VERSION_1;
  a.hdr.dcid_len = 8;
  a.hdr.scid_len = 0;
  CHECK(wired_srvboot_partial_ack(&a, wired_span_of(scid, 6), out, 288) > 0);
  CHECK(wired_srvboot_flight_pn(&a) == 3); /* the ack spent pn 2 */
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
  test_vneg_honors_version_mask();
  test_srvboot_accept_v2_initial();
  test_srvboot_v1_initial_with_vi_switches_to_v2();
  test_srvboot_iscid_validated();
  test_srvboot_tp_ranges_validated();
  test_srvboot_idle_timeout_negotiated();
  test_srvboot_flight_pn_continues_past_partial_ack();
}
