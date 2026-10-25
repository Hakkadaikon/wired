#include "app/http3/server/srvboot/srvboot.h"
#include "common/diag/error/error.h"
#include "ee_find.h"
#include "test.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/sni.h"
#include "tls/handshake/core/tls/x25519.h"
#include "transport/packet/build/initpkt/initpkt.h"
#include "transport/version/version/version.h"

/* Server identity / extension behavior on the shipping accept path
 * (wired_srvboot_accept -> wired_server -> sdrv): RFC 6066 3 server_name,
 * RFC 8446 4.3.1 EncryptedExtensions contents. The self-signed certificate
 * srvboot builds from cert_seed names "localhost". */

struct snisrv_fix {
  wired_server  s;
  wired_srvloop l;
};

/* A real ClientHello offering server_name sni (n 0: none) and ALPN h3. */
static usz snisrv_ch(u8* ch, usz cap, wired_span sni) {
  u8 cli_priv[32], cli_pub[32], rnd[32];
  for (usz i = 0; i < 32; i++) {
    cli_priv[i] = (u8)(i + 1);
    rnd[i]      = (u8)(0xa0 + i);
  }
  wired_x25519_base(cli_pub, cli_priv);
  return tls_client_hello(
      &(clienthello_in){rnd, cli_pub, sni, wired_span_of(0, 0)},
      &(wired_obuf){ch, cap, 0});
}

/* Boot one connection from a v1 Initial carrying ch; returns
 * wired_srvboot_accept's result. */
static int snisrv_boot(struct snisrv_fix* f, const u8* ch, usz ch_len) {
  static const u8 dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  u8              pkt[1300], srv_priv[32], srv_pub[32], seed[32];
  u8              init_buf[1500], flight_buf[4096];
  initpkt_desc    d = {
      wired_span_of(dcid, 8), wired_span_of(dcid, 4), wired_span_of(ch, ch_len),
      0, 0};
  wired_obuf         o         = obuf_of(pkt, sizeof pkt);
  wired_obuf         init_ob   = obuf_of(init_buf, sizeof init_buf);
  wired_obuf         flight_ob = obuf_of(flight_buf, sizeof flight_buf);
  wired_srvboot_out  out       = {&init_ob, &flight_ob, {0}, 0, 0};
  wired_srvboot_conn conn      = {&f->s, &f->l};
  wired_srvboot_id   id        = {0};
  wired_srvboot_in   in        = {&id, wired_mspan_of(pkt, 0)};
  for (usz i = 0; i < 32; i++) {
    srv_priv[i] = (u8)(0x40 + i);
    seed[i]     = (u8)(0x80 + i);
  }
  wired_x25519_base(srv_pub, srv_priv);
  CHECK(initpkt_build_ver(VERSION_1, &d, &o));
  in.dgram     = wired_mspan_of(pkt, o.len);
  id.priv      = srv_priv;
  id.pub       = srv_pub;
  id.cert_seed = seed;
  id.scid      = (const u8*)"SRVR";
  id.scid_len  = 4;
  id.random    = srv_priv;
  return wired_srvboot_accept(&conn, &in, &out);
}

/* RFC 6066 3 / RFC 8446 6.2: a server_name whose HostName is empty (the
 * length byte zeroed, the stray name byte left behind) is refused with
 * decode_error, not accepted as if no SNI had been sent. */
static void test_snisrv_malformed_sni_decode_error(void) {
  static struct snisrv_fix f;
  u8                       ch[512];
  wired_span               ext;
  usz n = snisrv_ch(ch, sizeof ch, wired_span_of((const u8*)"x", 1));
  CHECK(salpn_find_extension(wired_span_of(ch, n), SNI_TYPE, &ext));
  ch[(usz)(ext.p - ch) + 4] = 0; /* HostName length 1 -> 0 */
  f                         = (struct snisrv_fix){0};
  CHECK(snisrv_boot(&f, ch, n) == 0);
  CHECK(sdrv_last_error(&f.s.sdrv) == err_crypto(50));
  n = snisrv_ch(ch, sizeof ch, wired_span_of((const u8*)"localhost", 9));
  f = (struct snisrv_fix){0};
  CHECK(snisrv_boot(&f, ch, n) == 1);
}

/* The EncryptedExtensions the accepted connection sent: the transcript
 * message right after ServerHello. */
static const u8* snisrv_ee(const struct snisrv_fix* f) {
  return f->s.tr + f->s.tr_through_sh;
}

/* Boot from a fresh ClientHello offering sni. */
static void snisrv_boot_sni(struct snisrv_fix* f, wired_span sni) {
  u8  ch[512];
  usz n = snisrv_ch(ch, sizeof ch, sni);
  *f    = (struct snisrv_fix){0};
  CHECK(snisrv_boot(f, ch, n) == 1);
  CHECK(snisrv_ee(f)[0] == 0x08); /* HS_ENCRYPTED_EXT */
}

/* RFC 6066 3: the matched server_name chose the certificate, so a full
 * handshake echoes an empty server_name (type 0, length 0); with no SNI
 * offered nothing is echoed. RFC 8446 4.2.7: an x25519 share is this
 * server's first choice, so no supported_groups is sent. */
static void test_snisrv_ee_server_name_echo(void) {
  static struct snisrv_fix f;
  wired_span               d = {0, 0};
  snisrv_boot_sni(&f, wired_span_of((const u8*)"localhost", 9));
  CHECK(ee_find(snisrv_ee(&f), SNI_TYPE, &d));
  CHECK(d.n == 0);
  CHECK(!ee_find(snisrv_ee(&f), 0x000a, &d));
  snisrv_boot_sni(&f, wired_span_of(0, 0));
  CHECK(!ee_find(snisrv_ee(&f), SNI_TYPE, &d));
}

void test_sni_srv(void) {
  test_snisrv_malformed_sni_decode_error();
  test_snisrv_ee_server_name_echo();
}
