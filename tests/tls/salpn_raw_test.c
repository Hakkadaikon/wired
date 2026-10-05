#include "tls/ext/salpn/salpn_raw.h"

#include "app/http3/server/srvboot/srvboot.h"
#include "test.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/eebuild/eebuild.h"
#include "transport/packet/build/initpkt/initpkt.h"
#include "transport/version/version/version.h"

/* Raw-QUIC MoQT ALPN selection (plan 7.1 T-A1..T-A4): RFC 7301 3.1/3.2,
 * draft-ietf-moq-transport-18 3.1 / -19 3.1 / -22 6.2 ("moqt-" + NN). */

#define SRAW_LIST "moqt-22 moqt-19 moqt-18"

static int sraw_has(const char* list, const char* name, usz n) {
  return salpn_raw_list_has(list, (const u8*)name, n);
}

/* T-A1: exact, case-sensitive membership; prefixes/extensions, case
 * variants, the empty name, and a 0/empty list are never members. */
static void test_salpn_raw_list_has(void) {
  CHECK(sraw_has(SRAW_LIST, "moqt-19", 7) == 1);
  CHECK(sraw_has(SRAW_LIST, "moqt-22", 7) == 1);
  CHECK(sraw_has(SRAW_LIST, "moqt-18", 7) == 1);
  CHECK(sraw_has(SRAW_LIST, "moqt-1", 6) == 0);
  CHECK(sraw_has(SRAW_LIST, "moqt-190", 8) == 0);
  CHECK(sraw_has(SRAW_LIST, "MOQT-19", 7) == 0);
  CHECK(sraw_has(SRAW_LIST, "", 0) == 0);
  CHECK(sraw_has(0, "moqt-19", 7) == 0);
  CHECK(sraw_has("", "moqt-19", 7) == 0);
  CHECK(sraw_has(" moqt-19  moqt-18 ", "moqt-18", 7) == 1);
}

/* ProtocolNameList bytes: list_len(2) then (len(1) name)*. */
static const u8 sraw_18_h3[]    = {0x00, 0x0b, 0x07, 'm',  'o', 'q', 't',
                                   '-',  '1',  '8',  0x02, 'h', '3'};
static const u8 sraw_h3_22[]    = {0x00, 0x0b, 0x02, 'h', '3', 0x07, 'm',
                                   'o',  'q',  't',  '-', '2', '2'};
static const u8 sraw_moq00_18[] = {0x00, 0x0f, 0x06, 'm',  'o', 'q',
                                   '-',  '0',  '0',  0x07, 'm', 'o',
                                   'q',  't',  '-',  '1',  '8'};
static const u8 sraw_16[]       = {0x00, 0x08, 0x07, 'm', 'o',
                                   'q',  't',  '-',  '1', '6'};
static const u8 sraw_18[]       = {0x00, 0x08, 0x07, 'm', 'o',
                                   'q',  't',  '-',  '1', '8'};

static salpn_choice sraw_pick(
    const u8* l, usz n, const char* list, wired_span* tok) {
  return salpn_raw_pick(l, n, list, tok);
}

/* tok is a view into the configured list, not into the ClientHello. */
static int sraw_tok_is(wired_span tok, const char* list, usz off) {
  return tok.p == (const u8*)list + off && tok.n == 7;
}

/* T-A2: the client's order decides across h3 and raw ids. */
static void test_salpn_raw_pick_client_order(void) {
  static const char list[] = SRAW_LIST;
  wired_span        tok    = {0, 0};
  CHECK(sraw_pick(sraw_18_h3, sizeof sraw_18_h3, list, &tok) == SALPN_RAW);
  CHECK(sraw_tok_is(tok, list, 16));
  tok = wired_span_of(0, 0);
  CHECK(sraw_pick(sraw_h3_22, sizeof sraw_h3_22, list, &tok) == SALPN_H3);
  CHECK(tok.p == 0); /* untouched on a non-raw result */
  CHECK(
      sraw_pick(sraw_moq00_18, sizeof sraw_moq00_18, list, &tok) == SALPN_RAW);
  CHECK(sraw_tok_is(tok, list, 16));
  CHECK(sraw_pick(sraw_16, sizeof sraw_16, list, &tok) == SALPN_NONE);
}

/* T-A2: feature off (0 or empty list) is byte-identical to salpn_negotiate. */
static void test_salpn_raw_pick_off(void) {
  wired_span tok = {0, 0};
  CHECK(sraw_pick(sraw_18, sizeof sraw_18, 0, &tok) == SALPN_NONE);
  CHECK(sraw_pick(sraw_18, sizeof sraw_18, "", &tok) == SALPN_NONE);
  CHECK(sraw_pick(sraw_18_h3, sizeof sraw_18_h3, 0, &tok) == SALPN_H3);
  CHECK(
      sraw_pick(sraw_18_h3, sizeof sraw_18_h3, 0, &tok) ==
      salpn_negotiate(sraw_18_h3, sizeof sraw_18_h3));
  CHECK(tok.p == 0);
}

/* T-A3: malformed lists never select and never read out of bounds. */
static void test_salpn_raw_pick_malformed(void) {
  static const u8 overrun_list[] = {0x00, 0x09, 0x07, 'm', 'o',
                                    'q',  't',  '-',  '1', '8'};
  static const u8 zero_entry[]   = {0x00, 0x01, 0x00};
  static const u8 entry_over[]   = {0x00, 0x08, 0x08, 'm', 'o',
                                    'q',  't',  '-',  '1', '8'};
  wired_span      tok            = {0, 0};
  CHECK(sraw_pick(overrun_list, sizeof overrun_list, SRAW_LIST, &tok) == 0);
  CHECK(sraw_pick(zero_entry, sizeof zero_entry, SRAW_LIST, &tok) == 0);
  CHECK(sraw_pick(entry_over, sizeof entry_over, SRAW_LIST, &tok) == 0);
  CHECK(sraw_pick(sraw_18, 1, SRAW_LIST, &tok) == 0);
  CHECK(sraw_pick(0, 0, SRAW_LIST, &tok) == 0);
  CHECK(tok.p == 0);
}

/* T-A3: every truncation of a valid list stays in bounds (the buffer is
 * exactly n bytes) and only the full list selects. */
static void test_salpn_raw_pick_truncations(void) {
  u8 buf[sizeof sraw_moq00_18];
  for (usz n = 0; n <= sizeof sraw_moq00_18; n++) {
    wired_span tok = {0, 0};
    for (usz i = 0; i < n; i++) buf[i] = sraw_moq00_18[i];
    CHECK(
        (sraw_pick(buf, n, SRAW_LIST, &tok) == SALPN_RAW) ==
        (n == sizeof sraw_moq00_18));
  }
}

/* T-A4 pinned bytes (RFC 7301 3.1, hand-derived): ext type 0x0010, ext len
 * 10 = list_len(2) + name_len(1) + 7, list len 8, name len 7, "moqt-19". */
static void test_salpn_raw_ee_bytes(void) {
  static const u8   want[14]   = {0x00, 0x10, 0x00, 0x0a, 0x00, 0x08, 0x07,
                                  0x6d, 0x6f, 0x71, 0x74, 0x2d, 0x31, 0x39};
  static const u8   want_h3[9] = {0x00, 0x10, 0x00, 0x05, 0x00,
                                  0x03, 0x02, 0x68, 0x33};
  static const char list[]     = SRAW_LIST;
  u8                out[32];
  wired_obuf        ob  = obuf_of(out, sizeof out);
  wired_span        tok = wired_span_of((const u8*)list + 8, 7);
  CHECK(salpn_build_response_tok(salpn_choice_name(SALPN_RAW, tok), &ob));
  CHECK(ob.len == sizeof want);
  for (usz i = 0; i < sizeof want; i++) CHECK(out[i] == want[i]);
  ob = obuf_of(out, sizeof out);
  CHECK(salpn_build_response_tok(salpn_choice_name(SALPN_H3, tok), &ob));
  CHECK(ob.len == sizeof want_h3);
  for (usz i = 0; i < sizeof want_h3; i++) CHECK(out[i] == want_h3[i]);
  ob = obuf_of(out, sizeof out);
  CHECK(!salpn_build_response_tok(salpn_choice_name(SALPN_NONE, tok), &ob));
  CHECK(!salpn_build_response_tok(
      salpn_choice_name(SALPN_RAW, wired_span_of(0, 0)), &ob));
  ob = obuf_of(out, sizeof want - 1);
  CHECK(!salpn_build_response_tok(salpn_choice_name(SALPN_RAW, tok), &ob));
}

/* T-A4 end to end: EncryptedExtensions carries the moqt-19 ALPN extension
 * right after the extensions-block length (RFC 8446 4.3.1). */
static void test_salpn_raw_ee_message(void) {
  static const u8 want[14] = {0x00, 0x10, 0x00, 0x0a, 0x00, 0x08, 0x07,
                              0x6d, 0x6f, 0x71, 0x74, 0x2d, 0x31, 0x39};
  const u8        tp[1]    = {0xaa};
  u8              out[64];
  wired_obuf      ob = obuf_of(out, sizeof out);
  CHECK(eebuild_encrypted_extensions(
      wired_span_of((const u8*)"moqt-19", 7), wired_span_of(tp, 1), 0, &ob));
  for (usz i = 0; i < sizeof want; i++) CHECK(out[4 + 2 + i] == want[i]);
}

/* ---- S8: wired_srvboot_id.raw_alpns reaches the TLS layer ---- */

struct sraw_fix {
  wired_server  s;
  wired_srvloop l;
};

/* A real ClientHello whose only ALPN entry, "h3", is rewritten in place to
 * the same-length raw id "m9". */
static usz sraw_client_hello_m9(u8* ch, usz cap) {
  u8         cli_priv[32], cli_pub[32], rnd[32];
  wired_span ext = {0, 0};
  wired_obuf ob  = obuf_of(ch, cap);
  usz        n;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i] = (u8)(i + 1);
    rnd[i]      = (u8)(0xa0 + i);
  }
  wired_x25519_base(cli_pub, cli_priv);
  n = tls_client_hello(
      &(clienthello_in){rnd, cli_pub, wired_span_of(0, 0), wired_span_of(0, 0)},
      &ob);
  CHECK(salpn_find_extension(wired_span_of(ch, n), SALPN_EXT_TYPE, &ext));
  ch[(usz)(ext.p - ch) + 3] = 'm';
  ch[(usz)(ext.p - ch) + 4] = '9';
  return n;
}

/* Boot one connection from a v1 Initial carrying the "m9" ClientHello
 * with raw_alpns configured; returns wired_srvboot_accept's result. */
static int sraw_boot(struct sraw_fix* f, const char* raw_alpns) {
  static const u8 dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  u8              ch[512], pkt[1300], srv_priv[32], srv_pub[32], seed[32];
  u8              init_buf[1500], flight_buf[4096];
  usz             ch_len = sraw_client_hello_m9(ch, sizeof ch);
  initpkt_desc    d      = {
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
  id.raw_alpns = raw_alpns;
  return wired_srvboot_accept(&conn, &in, &out);
}

/* raw_alpns configured: the connection negotiates the raw id and the token
 * views the static configuration. Off: no_application_protocol (0x178). */
static void test_salpn_raw_srvboot(void) {
  static const char list[] = "moqt-19 m9";
  struct sraw_fix   f      = {0};
  CHECK(sraw_boot(&f, list) == 1);
  CHECK(f.s.sdrv.alpn == SALPN_RAW);
  CHECK(f.s.sdrv.alpn_tok.p == (const u8*)list + 8);
  CHECK(f.s.sdrv.alpn_tok.n == 2);
  f = (struct sraw_fix){0};
  CHECK(sraw_boot(&f, 0) == 0);
  CHECK(f.s.sdrv.alpn == SALPN_NONE);
  CHECK(sdrv_last_error(&f.s.sdrv) == 0x178);
}

void test_salpn_raw(void) {
  test_salpn_raw_list_has();
  test_salpn_raw_pick_client_order();
  test_salpn_raw_pick_off();
  test_salpn_raw_pick_malformed();
  test_salpn_raw_pick_truncations();
  test_salpn_raw_ee_bytes();
  test_salpn_raw_ee_message();
  test_salpn_raw_srvboot();
}
