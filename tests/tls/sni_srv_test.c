#include "app/http3/server/srvboot/srvboot.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/diag/error/error.h"
#include "ee_find.h"
#include "test.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/handshake.h"
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

/* ALPN configuration for snisrv_boot (wired_srvboot_id's fields). */
typedef struct {
  const char* raw_alpns;
  int         client_order;
} snisrv_alpn;

/* Boot one connection from a v1 Initial carrying ch, ALPN configured per
 * a (0: defaults); returns wired_srvboot_accept's result. */
static int snisrv_boot_alpn(
    struct snisrv_fix* f, const u8* ch, usz ch_len, const snisrv_alpn* a) {
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
  if (a) {
    id.raw_alpns         = a->raw_alpns;
    id.alpn_client_order = a->client_order;
  }
  return wired_srvboot_accept(&conn, &in, &out);
}

static int snisrv_boot(struct snisrv_fix* f, const u8* ch, usz ch_len) {
  return snisrv_boot_alpn(f, ch, ch_len, 0);
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

/* Offset of the ClientHello's extensions<2> length (RFC 8446 4.1.2: past
 * legacy_version, random, session_id, cipher_suites, compression). */
static usz snisrv_exts_off(const u8* ch) {
  usz off = 4 + 2 + 32;
  off += 1 + ch[off];
  off += 2 + ((usz)ch[off] << 8 | ch[off + 1]);
  return off + 1 + ch[off];
}

/* Rebuild ch (n bytes) into out with its ALPN extension_data replaced by
 * list (RFC 7301 3.1 ProtocolNameList bytes); returns the new length. */
static usz snisrv_set_alpn(
    const u8* ch, usz n, wired_span list, u8* out, usz cap) {
  wired_span ext;
  usz        at, tail, exts_off = snisrv_exts_off(ch);
  usz        exts;
  CHECK(salpn_find_extension(wired_span_of(ch, n), SALPN_EXT_TYPE, &ext));
  at   = (usz)(ext.p - ch);
  tail = n - at - ext.n;
  CHECK(at + list.n + tail <= cap);
  bytes_memcpy(out, ch, at);
  bytes_memcpy(out + at, list.p, list.n);
  bytes_memcpy(out + at + list.n, ch + at + ext.n, tail);
  be_put_be16(out + at - 2, (u16)list.n);
  exts = ((usz)ch[exts_off] << 8 | ch[exts_off + 1]) - ext.n + list.n;
  be_put_be16(out + exts_off, (u16)exts);
  hs_finish(out, at + list.n + tail);
  return at + list.n + tail;
}

/* Boot from a ClientHello offering ProtocolNameList list under a. */
static void snisrv_boot_list(
    struct snisrv_fix* f, const u8* list, usz n, const snisrv_alpn* a) {
  u8  ch[512], ch2[600];
  usz ch_len = snisrv_ch(ch, sizeof ch, wired_span_of(0, 0));
  usz len    = snisrv_set_alpn(ch, ch_len, wired_span_of(list, n), ch2, 600);
  *f         = (struct snisrv_fix){0};
  CHECK(snisrv_boot_alpn(f, ch2, len, a) == 1);
}

/* RFC 7301 3.2: the server selects its own most preferred protocol the
 * client offered -- raw ids (configured order), then h3, then hq-interop --
 * not the client's first. msquic's captured offer [hq-interop, h3, hq-29,
 * h3-29] gets h3, or hq-interop under alpn_client_order (the interop
 * image's setting); [h3, moqt-19] gets the configured moqt-19. */
static void test_snisrv_alpn_server_preference(void) {
  static const u8   msquic[28]    = {0x00, 0x1a, 0x0a, 0x68, 0x71, 0x2d, 0x69,
                                     0x6e, 0x74, 0x65, 0x72, 0x6f, 0x70, 0x02,
                                     0x68, 0x33, 0x05, 0x68, 0x71, 0x2d, 0x32,
                                     0x39, 0x05, 0x68, 0x33, 0x2d, 0x32, 0x39};
  static const u8   h3_moqt19[13] = {0x00, 0x0b, 0x02, 'h', '3', 0x07, 'm',
                                     'o',  'q',  't',  '-', '1', '9'};
  static const char raw[]         = "moqt-22 moqt-19";
  static struct snisrv_fix f;
  snisrv_alpn              client = {0, 1};
  snisrv_alpn              moqt   = {raw, 0};
  snisrv_boot_list(&f, msquic, sizeof msquic, 0);
  CHECK(f.s.sdrv.alpn == SALPN_H3);
  snisrv_boot_list(&f, msquic, sizeof msquic, &client);
  CHECK(f.s.sdrv.alpn == SALPN_HQ);
  snisrv_boot_list(&f, h3_moqt19, sizeof h3_moqt19, &moqt);
  CHECK(f.s.sdrv.alpn == SALPN_RAW);
  CHECK(f.s.sdrv.alpn_tok.p == (const u8*)raw + 8);
  CHECK(f.s.sdrv.alpn_tok.n == 7);
}

void test_sni_srv(void) {
  test_snisrv_alpn_server_preference();
  test_snisrv_malformed_sni_decode_error();
  test_snisrv_ee_server_name_echo();
}
