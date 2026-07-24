#include "tls/handshake/core/sdrv/sdrv.h"

#include <stdlib.h> /* malloc/free: hosted test build only, see test.h */

#include "app/datagram/datagram/datagram.h"
#include "common/bytes/util/be.h"
#include "common/diag/error/error.h"
#include "common/platform/clock/clock.h"
#include "crypto/pki/encoding/x509/ec_pubkey.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/castore.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "realchain_golden.h"
#include "test.h"
#include "tls/ext/stp/parse_tp.h"
#include "tls/ext/tlsext/earlydata.h"
#include "tls/ext/tlsext/preshared.h"
#include "tls/ext/tparam/tparam.h"
#include "tls/ext/tparam/tpcheck.h"
#include "tls/handshake/core/tls/binder.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tls/certverify.h"
#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/serverhello.h"
#include "tls/handshake/core/tls/tpext.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/keys/ticket/ticket.h"

/* RFC 8446 4 / RFC 9001 4: a client emits a ClientHello, the server driver
 * builds the real server flight, and the client reaches the same ECDHE shared
 * secret, verifies the CertificateVerify ECDSA P-256 signature against the
 * server's self-built P-256 certificate, and checks the Finished. */

/* Split the server flight (EE || Cert || CertVerify || Finished) into its four
 * messages by walking the 4-byte handshake headers. */
static int next_hs(const u8* b, usz n, usz* p, const u8** msg, usz* len) {
  usz body;
  u8  type;
  if (*p + 4 > n) return 0;
  if (quic_hs_parse(quic_span_of(b + *p, n - *p), &type, &body) != 4) return 0;
  *msg = b + *p;
  *len = 4 + body;
  *p += *len;
  return 1;
}

/* RFC 8446 4.1.2: splice a 32-byte legacy_session_id into a ClientHello that
 * was built with an empty one. Insert the 32 bytes after body offset 34 (the
 * session_id length byte), bump that byte to 32, and patch the 3-byte handshake
 * length. Returns the new total length. */
static usz ch_with_sid(u8* out, const u8* ch, usz ch_len, const u8 sid[32]) {
  usz tail = ch_len - (4 + 35); /* bytes after the len byte */
  for (usz i = 0; i < 4 + 35; i++) out[i] = ch[i];
  for (usz i = 0; i < 32; i++) out[4 + 35 + i] = sid[i];
  for (usz i = 0; i < tail; i++) out[4 + 35 + 32 + i] = ch[4 + 35 + i];
  out[4 + 34] = 32;
  quic_hs_finish(out, ch_len + 32);
  return ch_len + 32;
}

/* RFC 8446 4.1.3: the server echoes the client's legacy_session_id in the
 * ServerHello (legacy_session_id_echo). BoringSSL (curl/quiche) MUST-rejects a
 * mismatch with illegal_parameter, so a 32-byte session_id must round-trip. */
static void test_sdrv_session_id_echo(void) {
  u8        cli_priv[32], cli_pub[32], srv_priv[32], srv_pub[32], cert_priv[32];
  u8        ch[512], ch2[600], sh[256], flight[2048], srv_random[32], sid[32];
  usz       ch_len, ch2_len;
  quic_sdrv s;

  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_priv[i]   = (u8)(0x40 + i);
    cert_priv[i]  = (u8)(0x80 + i);
    srv_random[i] = (u8)(0xa0 + i);
    sid[i]        = (u8)(0x10 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  quic_x25519_base(srv_pub, srv_priv);

  ch_len = quic_tls_client_hello(
      &(quic_clienthello_in){
          srv_random, cli_pub, quic_span_of(0, 0), quic_span_of(0, 0)},
      &(quic_obuf){ch, sizeof(ch), 0});
  CHECK(ch_len != 0);
  ch2_len = ch_with_sid(ch2, ch, ch_len, sid);

  {
    quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0, 0, 0};
    quic_sdrv_init(&s, &din);
  }
  CHECK(quic_sdrv_recv_client_hello(&s, ch2, ch2_len));
  {
    quic_obuf            sh_ob = quic_obuf_of(sh, sizeof(sh));
    quic_obuf            fl_ob = quic_obuf_of(flight, sizeof(flight));
    quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
    CHECK(quic_sdrv_build_server_flight(&s, srv_random, &fo));
  }

  /* ServerHello legacy_session_id_echo sits at body offset 34: len byte then
   * the bytes. Header(4) + version(2) + random(32) = 38, len at sh[38]. */
  CHECK(sh[38] == 32);
  for (usz i = 0; i < 32; i++) CHECK(sh[39 + i] == sid[i]);

  /* TLS 1.3 native ClientHello (empty session_id) still works: echo len 0. */
  {
    quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0, 0, 0};
    quic_sdrv_init(&s, &din);
  }
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  {
    quic_obuf            sh_ob = quic_obuf_of(sh, sizeof(sh));
    quic_obuf            fl_ob = quic_obuf_of(flight, sizeof(flight));
    quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
    CHECK(quic_sdrv_build_server_flight(&s, srv_random, &fo));
  }
  CHECK(sh[38] == 0);
}

/* Build a ClientHello with a real x25519 key_share, sized for the caller. An
 * empty transport parameters TLV sequence (0 bytes) is a well-formed "no
 * parameters advertised" -- unlike a stray 1-byte payload, which reads as a
 * malformed single-byte id varint to any TLV-sequence walk (RFC 9000 18/7.4).
 */
static usz sdrv_test_client_hello(
    u8* ch, usz ch_cap, const u8* cli_pub, const u8* srv_random) {
  return quic_tls_client_hello(
      &(quic_clienthello_in){
          srv_random, cli_pub, quic_span_of(0, 0), quic_span_of(0, 0)},
      &(quic_obuf){ch, ch_cap, 0});
}

/* Drive an sdrv through ClientHello -> flight with in as the init params,
 * writing the flight bytes into sh/flight and their lengths into *sh_len /
 * *hs_len. */
static void sdrv_test_drive(
    quic_sdrv*               s,
    const quic_sdrv_init_in* in,
    const u8*                ch,
    usz                      ch_len,
    const u8*                srv_random,
    u8*                      sh,
    usz                      sh_cap,
    usz*                     sh_len,
    u8*                      flight,
    usz                      flight_cap,
    usz*                     hs_len) {
  quic_obuf            sh_ob = quic_obuf_of(sh, sh_cap);
  quic_obuf            fl_ob = quic_obuf_of(flight, flight_cap);
  quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
  quic_sdrv_init(s, in);
  CHECK(quic_sdrv_recv_client_hello(s, ch, ch_len));
  CHECK(quic_sdrv_build_server_flight(s, srv_random, &fo));
  *sh_len = sh_ob.len;
  *hs_len = fl_ob.len;
}

/* RFC 8446 4.4.2: driving sdrv with an externally issued [leaf, int] chain
 * sends that chain verbatim (no internally generated certificate), the
 * CertificateVerify verifies against the leaf's real key, and the parsed
 * chain plus the golden root validates as a path (RFC 5280 6.1). */
static void test_sdrv_external_chain(void) {
  u8        cli_priv[32], cli_pub[32], srv_priv[32], srv_pub[32];
  u8        ch[512], sh[256], flight[2048], srv_random[32];
  usz       ch_len, sh_len, hs_len, p = 0;
  const u8 *ee, *cm, *cv, *fin;
  usz       eel, cml, cvl, finl;
  u16       cv_scheme;
  quic_span cv_sig;
  quic_sdrv s;
  quic_span chain[2] = {
      quic_span_of(quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der)),
      quic_span_of(quic_realchain_int_der, sizeof(quic_realchain_int_der))};

  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_priv[i]   = (u8)(0x40 + i);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  quic_x25519_base(srv_pub, srv_priv);
  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);

  {
    quic_sdrv_init_in in = {
        srv_priv, srv_pub, quic_realchain_leaf_priv, chain, 2, 0, 0, 0};
    sdrv_test_drive(
        &s, &in, ch, ch_len, srv_random, sh, sizeof(sh), &sh_len, flight,
        sizeof(flight), &hs_len);
  }

  CHECK(next_hs(flight, hs_len, &p, &ee, &eel));
  CHECK(next_hs(flight, hs_len, &p, &cm, &cml));
  CHECK(next_hs(flight, hs_len, &p, &cv, &cvl));
  CHECK(next_hs(flight, hs_len, &p, &fin, &finl));

  /* the Certificate on the wire is the golden [leaf, int] chain verbatim,
   * not an internally generated one. */
  {
    quic_span               ctx;
    quic_tls_cert_entry     entries[QUIC_TLS_CERT_CHAIN_MAX];
    usz                     count;
    quic_tls_cert_chain_out co = {entries, QUIC_TLS_CERT_CHAIN_MAX, &count};
    CHECK(quic_tls_cert_chain(quic_span_of(cm + 4, cml - 4), &ctx, &co));
    CHECK(count == 2);
    CHECK(entries[0].cert_len == sizeof(quic_realchain_leaf_der));
    for (usz i = 0; i < entries[0].cert_len; i++)
      CHECK(entries[0].cert_data[i] == quic_realchain_leaf_der[i]);
    CHECK(entries[1].cert_len == sizeof(quic_realchain_int_der));
    for (usz i = 0; i < entries[1].cert_len; i++)
      CHECK(entries[1].cert_data[i] == quic_realchain_int_der[i]);

    /* CertificateVerify (scheme 0x0403) verifies against the golden leaf's
     * real public key over the transcript through Certificate. */
    {
      quic_transcript tr;
      u8              th[QUIC_SHA256_DIGEST];
      quic_transcript_init(&tr);
      quic_transcript_add(&tr, ch, ch_len);
      quic_transcript_add(&tr, sh, sh_len);
      quic_transcript_add(&tr, ee, eel);
      quic_transcript_add(&tr, cm, cml);
      quic_transcript_hash(&tr, th);
      CHECK(quic_tls_certverify_parse(
          quic_span_of(cv + 4, cvl - 4), &cv_scheme, &cv_sig));
      CHECK(cv_scheme == 0x0403);
      {
        quic_certverify_in cvin;
        cvin.scheme = 0x0403;
        cvin.cert   = quic_span_of(
            quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der));
        cvin.sig             = cv_sig;
        cvin.transcript_hash = th;
        CHECK(quic_tls_verify_cert_signature(&cvin));
      }
    }

    /* the parsed chain, plus the golden root as the trust anchor, validates
     * as an RFC 5280 6.1 path. */
    {
      quic_castore_entry roots[1];
      quic_castore       store;
      quic_span          path[3] = {
          quic_span_of(entries[0].cert_data, entries[0].cert_len),
          quic_span_of(entries[1].cert_data, entries[1].cert_len),
          quic_span_of(
              quic_realchain_root_der, sizeof(quic_realchain_root_der))};
      quic_castore_init(&store, roots, 1);
      CHECK(
          quic_castore_add(
              &store, quic_span_of(
                          quic_realchain_root_der,
                          sizeof(quic_realchain_root_der))) == 1);
      CHECK(quic_castore_validate_chain(&store, path, 3) == 1);
    }
  }
}

/* A CertificateVerify signed with an unrelated private key builds a flight
 * (sdrv does not check key/cert agreement) but fails leaf-key verification —
 * the mismatch is caught on the client side, not sdrv's. */
static void test_sdrv_external_chain_wrong_key(void) {
  u8        cli_priv[32], cli_pub[32], srv_priv[32], srv_pub[32];
  u8        wrong_priv[32];
  u8        ch[512], sh[256], flight[2048], srv_random[32];
  usz       ch_len, sh_len, hs_len, p = 0;
  const u8 *ee, *cm, *cv, *fin;
  usz       eel, cml, cvl, finl;
  u16       cv_scheme;
  quic_span cv_sig;
  quic_sdrv s;
  quic_span chain[2] = {
      quic_span_of(quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der)),
      quic_span_of(quic_realchain_int_der, sizeof(quic_realchain_int_der))};

  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_priv[i]   = (u8)(0x40 + i);
    srv_random[i] = (u8)(0xa0 + i);
    wrong_priv[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  quic_x25519_base(srv_pub, srv_priv);
  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);

  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, wrong_priv, chain, 2, 0, 0, 0};
    sdrv_test_drive(
        &s, &in, ch, ch_len, srv_random, sh, sizeof(sh), &sh_len, flight,
        sizeof(flight), &hs_len);
  }

  CHECK(next_hs(flight, hs_len, &p, &ee, &eel));
  CHECK(next_hs(flight, hs_len, &p, &cm, &cml));
  CHECK(next_hs(flight, hs_len, &p, &cv, &cvl));
  CHECK(next_hs(flight, hs_len, &p, &fin, &finl));

  {
    quic_transcript tr;
    u8              th[QUIC_SHA256_DIGEST];
    quic_transcript_init(&tr);
    quic_transcript_add(&tr, ch, ch_len);
    quic_transcript_add(&tr, sh, sh_len);
    quic_transcript_add(&tr, ee, eel);
    quic_transcript_add(&tr, cm, cml);
    quic_transcript_hash(&tr, th);
    CHECK(quic_tls_certverify_parse(
        quic_span_of(cv + 4, cvl - 4), &cv_scheme, &cv_sig));
    {
      quic_certverify_in cvin;
      cvin.scheme = 0x0403;
      cvin.cert   = quic_span_of(
          quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der));
      cvin.sig             = cv_sig;
      cvin.transcript_hash = th;
      CHECK(!quic_tls_verify_cert_signature(&cvin));
    }
  }
}

/* chain_count over QUIC_TLS_CERT_CHAIN_MAX(10) fails the flight closed:
 * nothing to send, quic_sdrv_build_server_flight returns 0. 11 entries (one
 * past the limit) alternating leaf/intermediate DER -- sdrv_take_chain's
 * count check fires before any entry is copied, so the flight buffer never
 * needs to actually hold 11 certificates worth of bytes. */
static void test_sdrv_chain_overflow(void) {
  u8        cli_priv[32], cli_pub[32], srv_priv[32], srv_pub[32];
  u8        cert_priv[32];
  u8        ch[512], sh[256], flight[2048], srv_random[32];
  usz       ch_len;
  quic_sdrv s;
  quic_span leaf =
      quic_span_of(quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der));
  quic_span intermediate =
      quic_span_of(quic_realchain_int_der, sizeof(quic_realchain_int_der));
  quic_span chain[11] = {leaf, intermediate, leaf, intermediate,
                         leaf, intermediate, leaf, intermediate,
                         leaf, intermediate, leaf};

  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_priv[i]   = (u8)(0x40 + i);
    cert_priv[i]  = (u8)(0x80 + i);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  quic_x25519_base(srv_pub, srv_priv);
  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);

  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, cert_priv, chain, 11, 0, 0, 0};
    quic_obuf         sh_ob = quic_obuf_of(sh, sizeof(sh));
    quic_obuf         fl_ob = quic_obuf_of(flight, sizeof(flight));
    quic_sdrv_flight_out fo = {&sh_ob, &fl_ob};
    quic_sdrv_init(&s, &in);
    CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
    CHECK(!quic_sdrv_build_server_flight(&s, srv_random, &fo));
  }
}

/* chain_count AT QUIC_TLS_CERT_CHAIN_MAX(10, the amplificationlimit
 * boundary minus one for the odd/even leaf-intermediate alternation) builds
 * successfully -- exercises the SDK's own real 9-cert amplificationlimit
 * target, one flight buffer sized for it (16KB, matching srvrun_conn's
 * boot_hs). */
static void test_sdrv_flight_nine_cert_chain(void) {
  u8        cli_priv[32], cli_pub[32], srv_priv[32], srv_pub[32];
  u8        cert_priv[32];
  u8        ch[512], sh[256], srv_random[32];
  static u8 flight[16384];
  usz       ch_len;
  quic_sdrv s;
  quic_span leaf =
      quic_span_of(quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der));
  quic_span chain[9] = {leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf};

  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_priv[i]   = (u8)(0x40 + i);
    cert_priv[i]  = (u8)(0x80 + i);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  quic_x25519_base(srv_pub, srv_priv);
  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);

  {
    quic_sdrv_init_in    in = {srv_priv, srv_pub, cert_priv, chain, 9, 0, 0, 0};
    quic_obuf            sh_ob = quic_obuf_of(sh, sizeof(sh));
    quic_obuf            fl_ob = quic_obuf_of(flight, sizeof(flight));
    quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
    quic_sdrv_init(&s, &in);
    CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
    CHECK(quic_sdrv_build_server_flight(&s, srv_random, &fo));
  }
}

/* Build a ClientHello with a real x25519 key_share and a caller-supplied
 * transport parameters blob tp (RFC 9001 8.2), so tests can pin
 * quic_sdrv_recv_client_hello's handling of specific parameters. */
static usz sdrv_test_client_hello_tp(
    u8* ch, usz ch_cap, const u8* cli_pub, const u8* srv_random, quic_span tp) {
  return quic_tls_client_hello(
      &(quic_clienthello_in){srv_random, cli_pub, quic_span_of(0, 0), tp},
      &(quic_obuf){ch, ch_cap, 0});
}

/* A fresh sdrv driver plus a ClientHello signing key pair, common to the
 * peer_max_datagram_frame_size tests below. */
static void sdrv_dgram_test_setup(
    quic_sdrv* s, u8 cli_pub[32], u8 srv_random[32]) {
  u8 cli_priv[32], srv_priv[32], srv_pub[32], cert_priv[32];
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_priv[i]   = (u8)(0x40 + i);
    cert_priv[i]  = (u8)(0x80 + i);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  quic_x25519_base(srv_pub, srv_priv);
  {
    quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0, 0, 0};
    quic_sdrv_init(s, &din);
  }
}

/* A ClientHello carrying max_datagram_frame_size in its transport parameters
 * makes quic_sdrv_recv_client_hello store the exact advertised value on
 * sdrv.peer_max_datagram_frame_size. */
static void test_sdrv_recv_client_hello_stores_peer_max_datagram_frame_size(
    void) {
  u8        cli_pub[32], srv_random[32];
  u8        tpbuf[16], ch[512];
  quic_obuf tob = quic_obuf_of(tpbuf, sizeof(tpbuf));
  usz       tp_len;
  usz       ch_len;
  quic_sdrv s;
  tp_len = quic_tparam_put_int(&tob, QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 65535);
  CHECK(tp_len != 0);
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello_tp(
      ch, sizeof(ch), cli_pub, srv_random, quic_span_of(tpbuf, tp_len));
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(s.peer_max_datagram_frame_size == 65535);
}

/* Absent-parameter case: the transport parameters extension is present but
 * does not carry max_datagram_frame_size -- the field must stay 0 (RFC 9221 3
 * is an optional parameter), and the handshake must still succeed. */
static void test_sdrv_recv_client_hello_no_max_datagram_param_stays_zero(void) {
  u8        cli_pub[32], srv_random[32];
  u8        tpbuf[16], ch[512];
  quic_obuf tob = quic_obuf_of(tpbuf, sizeof(tpbuf));
  usz       tp_len;
  usz       ch_len;
  quic_sdrv s;
  tp_len = quic_tparam_put_int(&tob, QUIC_TP_MAX_IDLE_TIMEOUT, 30000);
  CHECK(tp_len != 0);
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello_tp(
      ch, sizeof(ch), cli_pub, srv_random, quic_span_of(tpbuf, tp_len));
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(s.peer_max_datagram_frame_size == 0);
}

/* Absent-extension case: an older/non-WT ClientHello with no transport
 * parameters extension at all must still succeed, leaving the field at 0. */
static void test_sdrv_recv_client_hello_no_tp_ext_stays_zero(void) {
  u8        cli_pub[32], srv_random[32];
  u8        ch[512];
  usz       ch_len;
  quic_sdrv s;
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(s.peer_max_datagram_frame_size == 0);
}

/* RFC 9000 18.2: a ClientHello carrying initial_max_data in its transport
 * parameters makes quic_sdrv_recv_client_hello store the exact advertised
 * value on sdrv.peer_initial_max_data -- the connection-level send credit
 * this endpoint (the server) may use, before any MAX_DATA update. */
static void test_sdrv_recv_client_hello_stores_peer_initial_max_data(void) {
  u8        cli_pub[32], srv_random[32];
  u8        tpbuf[16], ch[512];
  quic_obuf tob = quic_obuf_of(tpbuf, sizeof(tpbuf));
  usz       tp_len;
  usz       ch_len;
  quic_sdrv s;
  tp_len = quic_tparam_put_int(&tob, QUIC_TP_INITIAL_MAX_DATA, 1048576);
  CHECK(tp_len != 0);
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello_tp(
      ch, sizeof(ch), cli_pub, srv_random, quic_span_of(tpbuf, tp_len));
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(s.peer_initial_max_data == 1048576);
}

/* RFC 9000 18.2's safe default: a TP extension present but without
 * initial_max_data leaves the send credit at 0 (send nothing), never an
 * uninitialized or stale value. */
static void test_sdrv_recv_client_hello_no_initial_max_data_stays_zero(void) {
  u8        cli_pub[32], srv_random[32];
  u8        tpbuf[16], ch[512];
  quic_obuf tob = quic_obuf_of(tpbuf, sizeof(tpbuf));
  usz       tp_len;
  usz       ch_len;
  quic_sdrv s;
  tp_len = quic_tparam_put_int(&tob, QUIC_TP_MAX_IDLE_TIMEOUT, 30000);
  CHECK(tp_len != 0);
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello_tp(
      ch, sizeof(ch), cli_pub, srv_random, quic_span_of(tpbuf, tp_len));
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(s.peer_initial_max_data == 0);
}

/* RFC 9000 18.2: a ClientHello carrying initial_max_stream_data_bidi_local
 * makes quic_sdrv_recv_client_hello store the exact advertised value --
 * the per-stream send credit for streams the CLIENT (the TP sender) itself
 * initiates, i.e. HTTP/3 request streams the server replies on. */
static void
test_sdrv_recv_client_hello_stores_peer_initial_max_stream_data_bidi_local(
    void) {
  u8        cli_pub[32], srv_random[32];
  u8        tpbuf[16], ch[512];
  quic_obuf tob = quic_obuf_of(tpbuf, sizeof(tpbuf));
  usz       tp_len;
  usz       ch_len;
  quic_sdrv s;
  tp_len = quic_tparam_put_int(
      &tob, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 262144);
  CHECK(tp_len != 0);
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello_tp(
      ch, sizeof(ch), cli_pub, srv_random, quic_span_of(tpbuf, tp_len));
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(s.peer_initial_max_stream_data_bidi_local == 262144);
}

/* Absent-parameter case, stream-level: the TP extension is present but
 * without initial_max_stream_data_bidi_local -- the per-stream send credit
 * stays 0 (send nothing on any stream until MAX_STREAM_DATA arrives). */
static void
test_sdrv_recv_client_hello_no_initial_max_stream_data_bidi_local_stays_zero(
    void) {
  u8        cli_pub[32], srv_random[32];
  u8        tpbuf[16], ch[512];
  quic_obuf tob = quic_obuf_of(tpbuf, sizeof(tpbuf));
  usz       tp_len;
  usz       ch_len;
  quic_sdrv s;
  tp_len = quic_tparam_put_int(&tob, QUIC_TP_MAX_IDLE_TIMEOUT, 30000);
  CHECK(tp_len != 0);
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello_tp(
      ch, sizeof(ch), cli_pub, srv_random, quic_span_of(tpbuf, tp_len));
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(s.peer_initial_max_stream_data_bidi_local == 0);
}

/* RFC 9000 18.2: a ClientHello carrying initial_max_stream_data_bidi_remote
 * makes quic_sdrv_recv_client_hello store the exact advertised value --
 * the per-stream send credit for bidi streams the REMOTE endpoint (this
 * server) initiates toward the TP sender, e.g. a server-opened WebTransport
 * bidi stream. */
static void
test_sdrv_recv_client_hello_stores_peer_initial_max_stream_data_bidi_remote(
    void) {
  u8        cli_pub[32], srv_random[32];
  u8        tpbuf[16], ch[512];
  quic_obuf tob = quic_obuf_of(tpbuf, sizeof(tpbuf));
  usz       tp_len;
  usz       ch_len;
  quic_sdrv s;
  tp_len = quic_tparam_put_int(
      &tob, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 131072);
  CHECK(tp_len != 0);
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello_tp(
      ch, sizeof(ch), cli_pub, srv_random, quic_span_of(tpbuf, tp_len));
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(s.peer_initial_max_stream_data_bidi_remote == 131072);
}

/* RFC 9000 18.2: a ClientHello carrying initial_max_stream_data_uni makes
 * quic_sdrv_recv_client_hello store the exact advertised value -- the
 * per-stream send credit for uni streams this server opens toward the TP
 * sender, e.g. a server-opened WebTransport uni stream. */
static void test_sdrv_recv_client_hello_stores_peer_initial_max_stream_data_uni(
    void) {
  u8        cli_pub[32], srv_random[32];
  u8        tpbuf[16], ch[512];
  quic_obuf tob = quic_obuf_of(tpbuf, sizeof(tpbuf));
  usz       tp_len;
  usz       ch_len;
  quic_sdrv s;
  tp_len =
      quic_tparam_put_int(&tob, QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 65536);
  CHECK(tp_len != 0);
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello_tp(
      ch, sizeof(ch), cli_pub, srv_random, quic_span_of(tpbuf, tp_len));
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(s.peer_initial_max_stream_data_uni == 65536);
}

/* Absent-parameter case for both server-initiated-stream credits: the TP
 * extension is present but carries neither 0x06 nor 0x07 -- both stay 0
 * (send nothing on a server-opened stream until MAX_STREAM_DATA arrives,
 * RFC 9000 18.2's safe default). */
static void
test_sdrv_recv_client_hello_no_server_initiated_stream_credit_stays_zero(void) {
  u8        cli_pub[32], srv_random[32];
  u8        tpbuf[16], ch[512];
  quic_obuf tob = quic_obuf_of(tpbuf, sizeof(tpbuf));
  usz       tp_len;
  usz       ch_len;
  quic_sdrv s;
  tp_len = quic_tparam_put_int(&tob, QUIC_TP_MAX_IDLE_TIMEOUT, 30000);
  CHECK(tp_len != 0);
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello_tp(
      ch, sizeof(ch), cli_pub, srv_random, quic_span_of(tpbuf, tp_len));
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(s.peer_initial_max_stream_data_bidi_remote == 0);
  CHECK(s.peer_initial_max_stream_data_uni == 0);
}

/* RFC 8446 4.1.2: the ClientHello's own extensions-length field sits right
 * after the fixed legacy_version(2) + random(32) + empty session_id(1) +
 * one cipher_suite(2+2) + null compression(1+1) prefix, i.e. at body offset
 * 41 (message offset 4 + 41 = 45). sdrv_test_client_hello/_tp always build
 * that exact fixed prefix shape, so the offset is stable across the tests
 * below rather than a magic number. */
#define SDRV_TEST_EXTS_LEN_OFF 45

/* Fixed offsets of the key_share and transport_parameters extension_type
 * fields within the ClientHellos built by sdrv_test_client_hello[_tp]:
 * append_core always emits supported_versions(3+4), supported_groups(4+4),
 * sig_algs(8+4), key_share(38+4) in that order right after the extensions-
 * length field (offset 41 in body / 45 in ch), so key_share's type field
 * sits at 45 + 2+4+2+4+8+4 = 74 (2-byte-aligned running sum: 43 -> supported_
 * versions header, 50 -> supported_groups header, 58 -> sig_algs header,
 * 70 -> key_share header, so its type field is at ch offset 74). ALPN(5+4)
 * follows key_share, then transport_parameters is always appended last, so
 * its type field is at 70+4+38 (past key_share) +4+5 (past ALPN) = 121 in
 * body, i.e. ch offset 125 -- independent of the TP payload's own length,
 * since everything before it is fixed-size. */
#define SDRV_TEST_KEYSHARE_TYPE_OFF 74
#define SDRV_TEST_TP_TYPE_OFF 125

/* transport_parameters is the last extension sdrv_test_client_hello[_tp]
 * appends (see SDRV_TEST_TP_TYPE_OFF's doc), so its TLV is always the final
 * header(4)+tp_len bytes of ch. Strip it -- extension_type(2)+extension_data
 * length(2)+tp_len -- and patch the extensions-length field and the
 * handshake length to match, producing a real ClientHello that carries no
 * quic_transport_parameters extension at all (RFC 9001 8.2). */
static usz sdrv_test_strip_tp_ext(u8* ch, usz ch_len, usz tp_len) {
  usz cut                        = 4 + tp_len;
  usz nlen                       = ch_len - cut;
  u16 exts_len                   = (u16)(((usz)ch[SDRV_TEST_EXTS_LEN_OFF] << 8 |
                                          ch[SDRV_TEST_EXTS_LEN_OFF + 1]) -
                                         cut);
  ch[SDRV_TEST_EXTS_LEN_OFF]     = (u8)(exts_len >> 8);
  ch[SDRV_TEST_EXTS_LEN_OFF + 1] = (u8)exts_len;
  quic_hs_finish(ch, nlen);
  return nlen;
}

/* RFC 9001 8.2: a ClientHello with the quic_transport_parameters extension
 * present is accepted and records no error. */
static void test_sdrv_recv_client_hello_tp_ext_present_ok(void) {
  u8        cli_pub[32], srv_random[32];
  u8        ch[512];
  usz       ch_len;
  quic_sdrv s;
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(quic_sdrv_last_error(&s) == 0);
}

/* RFC 9001 8.2: an endpoint MUST close the connection with a
 * missing_extension (RFC 8446 B.2 alert 109, so CRYPTO_ERROR 0x016d) error
 * when the ClientHello carries no quic_transport_parameters extension. */
static void test_sdrv_recv_client_hello_missing_tp_ext_rejected(void) {
  u8        cli_pub[32], srv_random[32];
  u8        ch[512];
  usz       ch_len;
  quic_sdrv s;
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  ch_len = sdrv_test_strip_tp_ext(ch, ch_len, 0);
  CHECK(!quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(quic_sdrv_last_error(&s) == 0x016d);
}

/* RFC 9000 7.4: a transport parameter id repeated in the ClientHello's
 * quic_transport_parameters extension MUST be rejected with
 * TRANSPORT_PARAMETER_ERROR (0x08). */
static void test_sdrv_recv_client_hello_dup_tp_rejected(void) {
  u8        cli_pub[32], srv_random[32];
  u8        tpbuf[32], ch[512];
  quic_obuf tob = quic_obuf_of(tpbuf, sizeof(tpbuf));
  usz       tp_len;
  usz       ch_len;
  quic_sdrv s;
  tp_len = quic_tparam_put_int(&tob, QUIC_TP_MAX_IDLE_TIMEOUT, 30000);
  CHECK(tp_len != 0);
  {
    quic_obuf tail = quic_obuf_of(tpbuf + tp_len, sizeof(tpbuf) - tp_len);
    usz       w    = quic_tparam_put_int(&tail, QUIC_TP_MAX_IDLE_TIMEOUT, 1000);
    CHECK(w != 0);
    tp_len += w;
  }
  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  ch_len = sdrv_test_client_hello_tp(
      ch, sizeof(ch), cli_pub, srv_random, quic_span_of(tpbuf, tp_len));
  CHECK(ch_len != 0);
  CHECK(!quic_sdrv_recv_client_hello(&s, ch, ch_len));
  CHECK(quic_sdrv_last_error(&s) == QUIC_ERR_TRANSPORT_PARAMETER_ERROR);
}

/* A driver initialized with an arbitrary-but-fixed key set, enough to drive
 * quic_sdrv_recv_client_hello in the malformed-input tests below (they never
 * reach build_server_flight, so the exact key values don't matter). */
static void sdrv_test_init_any(quic_sdrv* s) {
  u8 srv_priv[32], srv_pub[32], cert_priv[32];
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_priv[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);
  {
    quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0, 0, 0};
    quic_sdrv_init(s, &din);
  }
}

/* Copy n bytes into a heap buffer allocated at EXACTLY n bytes (no slack) so
 * any out-of-bounds read past it is a real heap-buffer-overflow that
 * AddressSanitizer (or, on glibc, malloc's own guard pages under enough
 * pressure) catches deterministically -- unlike a stack/VLA buffer, whose
 * surrounding frame may contain readable padding that lets an overrun read
 * silently succeed instead of crashing. */
static u8* sdrv_test_malloc_exact(const u8* src, usz n) {
  u8* p = malloc(n);
  for (usz i = 0; i < n; i++) p[i] = src[i];
  return p;
}

/* Overwrite a 2-byte big-endian extension_type field at ch[off] with a value
 * that never matches a real registered type used in these ClientHellos, so
 * the walk being tested cannot short-circuit by finding its target extension
 * before reaching the corrupted tail -- it must keep scanning, which is what
 * turns the overclaimed extensions-length into a genuine out-of-bounds read
 * instead of a walk that happens to succeed first. */
static void sdrv_test_blot_ext_type(u8* ch, usz off) {
  ch[off]     = 0xba;
  ch[off + 1] = 0xad;
}

/* A ClientHello whose self-reported extensions length claims far more bytes
 * than actually remain in the real (exactly-sized) buffer must not walk past
 * it while scanning for key_share -- it is a malformed ClientHello and must
 * be rejected (0), not read out of bounds. The key_share extension's own
 * type field is blotted out so the walk cannot return early on a match
 * before reaching the real end of the buffer, forcing it to actually run
 * into the overclaimed (out-of-bounds) tail. */
static void test_sdrv_keyshare_walk_rejects_overclaimed_exts_len(void) {
  u8        cli_priv[32], cli_pub[32], srv_random[32], scratch[512], *ch;
  usz       ch_len;
  quic_sdrv s;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  ch_len =
      sdrv_test_client_hello(scratch, sizeof(scratch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  ch                             = sdrv_test_malloc_exact(scratch, ch_len);
  ch[SDRV_TEST_EXTS_LEN_OFF]     = 0xff;
  ch[SDRV_TEST_EXTS_LEN_OFF + 1] = 0xff;
  sdrv_test_blot_ext_type(ch, SDRV_TEST_KEYSHARE_TYPE_OFF);
  sdrv_test_init_any(&s);
  CHECK(!quic_sdrv_recv_client_hello(&s, ch, ch_len));
  free(ch);
}

/* Same corruption, targeting the transport-parameters walk specifically: a
 * ClientHello carrying a real transport_parameters extension, but whose
 * outer extensions-length claims far more than the real buffer holds, must
 * not let find_client_tp_ext walk out of bounds either. The key_share
 * extension is left intact (so the earlier key_share walk in
 * quic_sdrv_recv_client_hello still succeeds normally and control reaches
 * the transport-parameters walk); the TP extension's own type field is
 * blotted out so THAT walk cannot return early either. */
static void test_sdrv_tp_walk_rejects_overclaimed_exts_len(void) {
  u8  cli_priv[32], cli_pub[32], srv_random[32], scratch[512], tpbuf[16], *ch;
  usz ch_len, tp_len;
  quic_obuf tob = quic_obuf_of(tpbuf, sizeof(tpbuf));
  quic_sdrv s;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  tp_len = quic_tparam_put_int(&tob, QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 65535);
  CHECK(tp_len != 0);
  ch_len = sdrv_test_client_hello_tp(
      scratch, sizeof(scratch), cli_pub, srv_random,
      quic_span_of(tpbuf, tp_len));
  CHECK(ch_len != 0);
  ch                             = sdrv_test_malloc_exact(scratch, ch_len);
  ch[SDRV_TEST_EXTS_LEN_OFF]     = 0xff;
  ch[SDRV_TEST_EXTS_LEN_OFF + 1] = 0xff;
  sdrv_test_blot_ext_type(ch, SDRV_TEST_TP_TYPE_OFF);
  sdrv_test_init_any(&s);
  CHECK(!quic_sdrv_recv_client_hello(&s, ch, ch_len));
  free(ch);
}

/* A single extension whose OWN length field claims more bytes than remain
 * in an otherwise validly-clamped extensions list must also be rejected,
 * not just an overclaimed outer extensions-length. The first extension after
 * the extensions-length field is supported_versions; its own 2-byte
 * ext_data length sits right after its 2-byte type. */
static void test_sdrv_keyshare_walk_rejects_overclaimed_ext_payload_len(void) {
  u8        cli_priv[32], cli_pub[32], srv_random[32], scratch[512], *ch;
  usz       ch_len, first_ext_len_off;
  quic_sdrv s;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  ch_len =
      sdrv_test_client_hello(scratch, sizeof(scratch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  ch                        = sdrv_test_malloc_exact(scratch, ch_len);
  first_ext_len_off         = SDRV_TEST_EXTS_LEN_OFF + 2 + 2;
  ch[first_ext_len_off]     = 0xff;
  ch[first_ext_len_off + 1] = 0xff;
  sdrv_test_init_any(&s);
  CHECK(!quic_sdrv_recv_client_hello(&s, ch, ch_len));
  free(ch);
}

/* Boundary: the extensions-length field exactly equal to the real remaining
 * bytes (no corruption at all -- this is simply a genuine, well-formed
 * ClientHello built at its exact real size) must still parse successfully.
 * Proves the fix does not reject valid input off-by-one. */
static void test_sdrv_keyshare_walk_accepts_exact_exts_len(void) {
  u8        cli_priv[32], cli_pub[32], srv_random[32], scratch[512], *ch;
  usz       ch_len;
  quic_sdrv s;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  ch_len =
      sdrv_test_client_hello(scratch, sizeof(scratch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  ch = sdrv_test_malloc_exact(scratch, ch_len);
  sdrv_test_init_any(&s);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  free(ch);
}

/* The message-level offset of the single cipher_suites entry that
 * sdrv_test_client_hello builds (RFC 8446 4.1.2: legacy_version(2)
 * random(32) session_id_len(1)=0 cipher_suites_len(2)=2 cipher_suites(2)),
 * right after the 4-byte handshake header put_prefix begins writing at
 * (quic_hs_begin returns 4): 4 + 2 + 32 + 1 + 2 = 41. */
#define SDRV_TEST_CIPHER_SUITE_OFF 41

/* The message-level offset of the ServerHello.cipher_suite field that
 * shb_prefix writes (RFC 8446 4.1.3): legacy_version(2) random(32)
 * session_id_len(1)=0 (no length-prefixed cipher_suites vector here, unlike
 * the ClientHello -- ServerHello.cipher_suite is a single bare value), right
 * after the 4-byte handshake header: 4 + 2 + 32 + 1 = 39 (sdrv_test_
 * client_hello's ClientHello always has an empty legacy_session_id, so sdrv
 * always echoes an empty session_id_echo here too). */
#define SDRV_TEST_SH_CIPHER_SUITE_OFF 39

/* Overwrite the single cipher_suites entry sdrv_test_client_hello built with
 * suite (big-endian). */
static void sdrv_test_set_suite(u8* ch, u16 suite) {
  ch[SDRV_TEST_CIPHER_SUITE_OFF]     = (u8)(suite >> 8);
  ch[SDRV_TEST_CIPHER_SUITE_OFF + 1] = (u8)suite;
}

/* Splice a second cipher_suites entry (prepended before the existing single
 * entry) into a ClientHello built by sdrv_test_client_hello, bumping the
 * cipher_suites length field from 2 to 4 and patching the 3-byte handshake
 * length. Returns the new total length. Mirrors ch_with_sid's session_id
 * splice above. */
static usz sdrv_test_prepend_suite(
    u8* out, const u8* ch, usz ch_len, u16 suite) {
  usz tail = ch_len - SDRV_TEST_CIPHER_SUITE_OFF;
  for (usz i = 0; i < SDRV_TEST_CIPHER_SUITE_OFF; i++) out[i] = ch[i];
  out[SDRV_TEST_CIPHER_SUITE_OFF]     = (u8)(suite >> 8);
  out[SDRV_TEST_CIPHER_SUITE_OFF + 1] = (u8)suite;
  for (usz i = 0; i < tail; i++)
    out[SDRV_TEST_CIPHER_SUITE_OFF + 2 + i] =
        ch[SDRV_TEST_CIPHER_SUITE_OFF + i];
  /* cipher_suites length field is 2 bytes before the first entry. */
  out[SDRV_TEST_CIPHER_SUITE_OFF - 2] = 0;
  out[SDRV_TEST_CIPHER_SUITE_OFF - 1] = 4;
  quic_hs_finish(out, ch_len + 2);
  return ch_len + 2;
}

/* Build a well-formed ClientHello and drive it to a built server flight;
 * CHECKs recv_client_hello and build_server_flight both succeed. Returns the
 * negotiated cipher_suite the caller can inspect on s, and the ServerHello
 * bytes in sh (sh_len). */
static void sdrv_test_negotiate(
    quic_sdrv* s, const u8* ch, usz ch_len, u8* sh, usz sh_cap, usz* sh_len) {
  u8                srv_priv[32], srv_pub[32], cert_priv[32], srv_random[32];
  u8                flight[2048];
  usz               hs_len;
  quic_sdrv_init_in in;
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]   = (u8)(0x40 + i);
    cert_priv[i]  = (u8)(0x80 + i);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);
  in = (quic_sdrv_init_in){srv_priv, srv_pub, cert_priv, 0, 0, 0, 0, 0};
  sdrv_test_drive(
      s, &in, ch, ch_len, srv_random, sh, sh_cap, sh_len, flight,
      sizeof(flight), &hs_len);
}

/* A single AES_128_GCM_SHA256 offer negotiates AES_128_GCM_SHA256, echoed in
 * the ServerHello.cipher_suite field. */
static void test_sdrv_suite_aes_only(void) {
  u8        cli_priv[32], cli_pub[32], srv_random[32], ch[512], sh[256];
  usz       ch_len, sh_len;
  quic_sdrv s;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  sdrv_test_set_suite(ch, QUIC_TLS_AES_128_GCM_SHA256);

  sdrv_test_negotiate(&s, ch, ch_len, sh, sizeof(sh), &sh_len);
  CHECK(s.cipher_suite == QUIC_TLS_AES_128_GCM_SHA256);
  CHECK(
      (u16)(sh[SDRV_TEST_SH_CIPHER_SUITE_OFF] << 8 |
            sh[SDRV_TEST_SH_CIPHER_SUITE_OFF + 1]) ==
      QUIC_TLS_AES_128_GCM_SHA256);
}

/* A single CHACHA20_POLY1305_SHA256 offer negotiates CHACHA20_POLY1305_
 * SHA256 (the only overlap), echoed in the ServerHello. This is the exact
 * shape quic-go sends when configured chacha20-only for interop. */
static void test_sdrv_suite_chacha_only(void) {
  u8        cli_priv[32], cli_pub[32], srv_random[32], ch[512], sh[256];
  usz       ch_len, sh_len;
  quic_sdrv s;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  sdrv_test_set_suite(ch, QUIC_TLS_CHACHA20_POLY1305_SHA256);

  sdrv_test_negotiate(&s, ch, ch_len, sh, sizeof(sh), &sh_len);
  CHECK(s.cipher_suite == QUIC_TLS_CHACHA20_POLY1305_SHA256);
  CHECK(
      (u16)(sh[SDRV_TEST_SH_CIPHER_SUITE_OFF] << 8 |
            sh[SDRV_TEST_SH_CIPHER_SUITE_OFF + 1]) ==
      QUIC_TLS_CHACHA20_POLY1305_SHA256);
}

/* Offering both CHACHA20_POLY1305_SHA256 and AES_128_GCM_SHA256 (in that
 * wire order) still negotiates AES_128_GCM_SHA256: RFC 8446 B.4 priority is
 * the server's choice, independent of the client's offer order. */
static void test_sdrv_suite_prefers_aes(void) {
  u8        cli_priv[32], cli_pub[32], srv_random[32];
  u8        ch[512], ch2[600], sh[256];
  usz       ch_len, ch2_len, sh_len;
  quic_sdrv s;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  sdrv_test_set_suite(ch, QUIC_TLS_CHACHA20_POLY1305_SHA256);
  ch2_len = sdrv_test_prepend_suite(
      ch2, ch, ch_len, QUIC_TLS_CHACHA20_POLY1305_SHA256);
  /* now offers [CHACHA20_POLY1305_SHA256, CHACHA20_POLY1305_SHA256]; patch
   * the second (originally-single) entry back to AES so the offer is
   * [CHACHA, AES] -- CHACHA first, AES second, AES must still win. */
  sdrv_test_set_suite(
      ch2 + 2, QUIC_TLS_AES_128_GCM_SHA256); /* shifted by the +2 splice */

  sdrv_test_negotiate(&s, ch2, ch2_len, sh, sizeof(sh), &sh_len);
  CHECK(s.cipher_suite == QUIC_TLS_AES_128_GCM_SHA256);
}

/* A suite this SDK implements neither AEAD for (AES_256_GCM_SHA384, no
 * SHA-384 key schedule) has no overlap with [AES_128, CHACHA20] -- the
 * handshake must fail rather than fall back to an unconfigured suite (the
 * bug this whole feature fixes: silently keying with a suite the peer never
 * agreed to). */
static void test_sdrv_suite_no_overlap_fails(void) {
  u8  cli_priv[32], cli_pub[32], srv_random[32], srv_priv[32], srv_pub[32];
  u8  cert_priv[32], ch[512];
  usz ch_len;
  quic_sdrv s;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_priv[i]   = (u8)(0x40 + i);
    cert_priv[i]  = (u8)(0x80 + i);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  quic_x25519_base(srv_pub, srv_priv);
  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  sdrv_test_set_suite(ch, QUIC_TLS_AES_256_GCM_SHA384);

  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, cert_priv, 0, 0, 0, 0, 0};
    quic_sdrv_init(&s, &in);
  }
  CHECK(!quic_sdrv_recv_client_hello(&s, ch, ch_len));
}

/* A cipher_suites vector whose declared byte length is odd (not a whole
 * number of 2-byte suites) is rejected outright rather than truncated or
 * read past its real end -- built at its exact real size (sdrv_test_
 * malloc_exact) so any overread is a real heap-buffer-overflow under
 * AddressSanitizer, not a silently-succeeding read into stack padding. */
static void test_sdrv_suite_malformed_vec(void) {
  u8        cli_priv[32], cli_pub[32], srv_random[32], scratch[512], *ch;
  usz       ch_len;
  quic_sdrv s;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  ch_len =
      sdrv_test_client_hello(scratch, sizeof(scratch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  /* cipher_suites length field (2 bytes before the entry) claims 3 bytes: odd,
   * not a whole number of suites. */
  scratch[SDRV_TEST_CIPHER_SUITE_OFF - 1] = 3;
  ch = sdrv_test_malloc_exact(scratch, ch_len);
  sdrv_test_init_any(&s);
  CHECK(!quic_sdrv_recv_client_hello(&s, ch, ch_len));
  free(ch);
}

/* A cipher_suites vector whose declared byte length overruns the real
 * ClientHello body must also be rejected, not read past the buffer -- same
 * exact-size-allocation technique as the odd-length case above. */
static void test_sdrv_suite_vec_overruns_body(void) {
  u8        cli_priv[32], cli_pub[32], srv_random[32], scratch[512], *ch;
  usz       ch_len;
  quic_sdrv s;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  ch_len =
      sdrv_test_client_hello(scratch, sizeof(scratch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  /* cipher_suites length field claims 0xfffe bytes -- wildly past the real
   * ClientHello body. */
  scratch[SDRV_TEST_CIPHER_SUITE_OFF - 2] = 0xff;
  scratch[SDRV_TEST_CIPHER_SUITE_OFF - 1] = 0xfe;
  ch = sdrv_test_malloc_exact(scratch, ch_len);
  sdrv_test_init_any(&s);
  CHECK(!quic_sdrv_recv_client_hello(&s, ch, ch_len));
  free(ch);
}

/* RFC 9000 7.3 / RFC 9001 5.2, post-Retry accept: original_destination_
 * connection_id in the EncryptedExtensions transport parameters must carry
 * the true first Initial's DCID (token-recovered), NOT the Initial-key
 * derivation input (the Retry's own SCID) -- quic_sdrv_set_cids_retried
 * keeps the two separate (sdrv.h), and emit_ee must advertise the former
 * (s->tp_odcid) while s->odcid stays the latter for key derivation. */
static void test_sdrv_retry_advertises_true_odcid_not_key_derivation_dcid(
    void) {
  static const u8 retry_scid[]  = {0x11, 0x22, 0x33, 0x44};
  static const u8 server_scid[] = {0xaa, 0xbb, 0xcc};
  static const u8 true_odcid[]  = {0x83, 0x94, 0xc8, 0xf0,
                                   0x3e, 0x51, 0x57, 0x08};
  u8              cli_pub[32], srv_random[32], ch[512], sh[256], flight[2048];
  usz             ch_len, hs_len, p = 0;
  const u8*       ee;
  usz             eel;
  quic_span       tp, cid;
  quic_stp_out    cido = {0, &cid};
  quic_sdrv       s;

  sdrv_dgram_test_setup(&s, cli_pub, srv_random);
  CHECK(quic_sdrv_set_cids_retried(
      &s, quic_span_of(retry_scid, sizeof(retry_scid)),
      quic_span_of(server_scid, sizeof(server_scid)),
      quic_span_of(true_odcid, sizeof(true_odcid))));

  /* odcid (key derivation) is the Retry's SCID; tp_odcid (TP advert) is the
   * true original -- the two must not collapse into one field. */
  CHECK(s.odcid_len == sizeof(retry_scid));
  CHECK(quic_tparam_cid_match(
      quic_span_of(s.odcid, s.odcid_len),
      quic_span_of(retry_scid, sizeof(retry_scid))));
  CHECK(s.tp_odcid_len == sizeof(true_odcid));
  CHECK(quic_tparam_cid_match(
      quic_span_of(s.tp_odcid, s.tp_odcid_len),
      quic_span_of(true_odcid, sizeof(true_odcid))));

  ch_len = sdrv_test_client_hello(ch, sizeof(ch), cli_pub, srv_random);
  CHECK(ch_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  {
    quic_obuf            sh_ob = quic_obuf_of(sh, sizeof(sh));
    quic_obuf            fl_ob = quic_obuf_of(flight, sizeof(flight));
    quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
    CHECK(quic_sdrv_build_server_flight(&s, srv_random, &fo));
    hs_len = fl_ob.len;
  }
  CHECK(next_hs(flight, hs_len, &p, &ee, &eel));
  CHECK(quic_tpext_decode(quic_span_of(ee + 15, eel - 15), &tp) != 0);

  /* the wire TP is the true ODCID, never the Retry SCID used for keys. */
  CHECK(
      quic_stp_parse(tp, QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, &cido) ==
      1);
  CHECK(
      cid.n == sizeof(true_odcid) &&
      quic_tparam_cid_match(cid, quic_span_of(true_odcid, sizeof(true_odcid))));
  CHECK(!quic_tparam_cid_match(
      cid, quic_span_of(retry_scid, sizeof(retry_scid))));
}

/* RFC 8446 4.2.11: append a pre_shared_key extension (single identity, single
 * binder) to the tail of a ClientHello previously built by
 * sdrv_test_client_hello (which has a fixed extensions layout: no session_id,
 * one cipher suite -- see put_prefix), and patch both the extensions-length
 * field and the handshake-message length. pre_shared_key MUST be the last
 * extension, so this is a pure append, no splice. Returns the new total
 * length, or 0 if out is too small. Also sets *psk_ext_off to the
 * extension's own TLV offset within out (header included) -- tests need this
 * to independently recompute the binder truncation point. */
static usz sdrv_test_append_psk(
    u8*                       out,
    usz                       out_cap,
    const u8*                 ch,
    usz                       ch_len,
    const quic_tlsext_psk_in* psk,
    usz*                      psk_ext_off) {
  /* Extensions-length field sits right after the fixed prefix: header(4) +
   * legacy_version+random(34) + session_id_len(1)=0 + cipher_suites(2+2) +
   * compression_methods(1+1) = 45, matching put_prefix's `off + 41` (body
   * offset 41) plus the 4-byte handshake header. */
  usz       exts_len_off = 45;
  usz       old_exts_len;
  u8        scratch[128];
  quic_obuf eob = quic_obuf_of(scratch, sizeof(scratch));
  if (!quic_tlsext_pre_shared_key(psk, &eob)) return 0;
  if (ch_len + eob.len > out_cap) return 0;
  for (usz i = 0; i < ch_len; i++) out[i] = ch[i];
  old_exts_len = (usz)out[exts_len_off] << 8 | out[exts_len_off + 1];
  *psk_ext_off = ch_len;
  for (usz i = 0; i < eob.len; i++) out[ch_len + i] = scratch[i];
  quic_put_be16(out + exts_len_off, (u16)(old_exts_len + eob.len));
  quic_hs_finish(out, ch_len + eob.len);
  return ch_len + eob.len;
}

/* RFC 8446 4.2.10/4.2.11: append the empty early_data extension (0x002a)
 * followed by a pre_shared_key extension (single identity, single binder) --
 * pre_shared_key MUST stay the last extension (4.2.11), so early_data goes
 * first. Same offset accounting as sdrv_test_append_psk; *psk_ext_off is set
 * to the pre_shared_key TLV's own offset (after early_data), matching what
 * sdrv_test_psk_truncate_len expects. */
static usz sdrv_test_append_early_data_then_psk(
    u8*                       out,
    usz                       out_cap,
    const u8*                 ch,
    usz                       ch_len,
    const quic_tlsext_psk_in* psk,
    usz*                      psk_ext_off) {
  usz       exts_len_off = 45;
  usz       old_exts_len;
  u8        ed[4];
  usz       ed_len;
  u8        scratch[128];
  quic_obuf eob = quic_obuf_of(scratch, sizeof(scratch));
  if (!quic_tlsext_early_data_ch(ed, sizeof(ed), &ed_len)) return 0;
  if (!quic_tlsext_pre_shared_key(psk, &eob)) return 0;
  if (ch_len + ed_len + eob.len > out_cap) return 0;
  for (usz i = 0; i < ch_len; i++) out[i] = ch[i];
  old_exts_len = (usz)out[exts_len_off] << 8 | out[exts_len_off + 1];
  for (usz i = 0; i < ed_len; i++) out[ch_len + i] = ed[i];
  *psk_ext_off = ch_len + ed_len;
  for (usz i = 0; i < eob.len; i++) out[ch_len + ed_len + i] = scratch[i];
  quic_put_be16(out + exts_len_off, (u16)(old_exts_len + ed_len + eob.len));
  quic_hs_finish(out, ch_len + ed_len + eob.len);
  return ch_len + ed_len + eob.len;
}

/* RFC 8446 4.2.11.2: the truncation point (right before the binders_len
 * field), independently derived from the wire layout for tests -- see
 * sdrv_psk_truncate's doc in sdrv.c for the byte accounting. */
static usz sdrv_test_psk_truncate_len(usz psk_ext_off, usz id_len) {
  return psk_ext_off + 12 + id_len;
}

/* RFC 8446 4.6.1: the PSK a ticket actually offers is derived from the
 * resumption_master_secret this SDK stores in quic_ticket.secret --
 * HKDF-Expand-Label(res_master_secret, "resumption", ticket_nonce, 32),
 * empty ticket_nonce (see newsessionticket.h/sdrv.c's sdrv_psk_from_ticket_
 * secret). Test-side mirror so fixtures compute a binder over the same PSK
 * sdrv.c will derive when it opens the ticket. */
static void sdrv_test_psk_from_res_master(
    const u8 res_master_secret[QUIC_TICKET_SECRET_LEN], u8 psk_out[32]) {
  quic_hkdf_label l = {"resumption", 10, {0, 0}};
  quic_hkdf_expand_label(res_master_secret, &l, quic_mspan_of(psk_out, 32));
}

/* A resumption PSK setup shared by the accept/fallback/abort tests: an sdrv
 * with a fixed ticket_key, a plain ClientHello, and a sealed ticket whose
 * resumption_master_secret (secret) and the PSK actually derived from it
 * (psk) are both known to the test. */
typedef struct {
  u8  ticket_key[QUIC_TICKET_KEY_LEN];
  u8  secret[QUIC_TICKET_SECRET_LEN]; /* resumption_master_secret */
  u8  psk[32];                        /* HKDF-Expand-Label(secret, ...) */
  u8  sealed[QUIC_TICKET_SEALED_LEN];
  u8  ch[600];
  usz ch_len;
  u8  cli_pub[32], srv_random[32];
} sdrv_psk_fixture;

static void sdrv_psk_fixture_init(sdrv_psk_fixture* f) {
  u8          cli_priv[32];
  quic_ticket t = {{0}, 0, 7200, 0};
  /* RFC 8446 4.2.11.1: issued "now" and the PSK offer's ticket_age claims 0ms
   * elapsed (set where the offer is built) -- freshness holds trivially so
   * these fixtures exercise 0-RTT accept/reject on their own axis, not on
   * ticket age. */
  t.issued_at = quic_clock_epoch_secs();
  for (usz i = 0; i < 32; i++) {
    f->ticket_key[i] = (u8)(0xc0 + i);
    cli_priv[i]      = (u8)(i + 1);
    f->srv_random[i] = (u8)(0xa0 + i);
  }
  for (usz i = 0; i < QUIC_TICKET_SECRET_LEN; i++) {
    f->secret[i] = (u8)(0x50 + i);
    t.secret[i]  = f->secret[i];
  }
  sdrv_test_psk_from_res_master(f->secret, f->psk);
  quic_x25519_base(f->cli_pub, cli_priv);
  quic_ticket_seal(&t, f->ticket_key, f->sealed);
  f->ch_len =
      sdrv_test_client_hello(f->ch, sizeof(f->ch), f->cli_pub, f->srv_random);
  CHECK(f->ch_len != 0);
}

/* A ClientHello with no pre_shared_key extension is completely
 * unaffected by resumption support being enabled -- same acceptance, same
 * psk_accepted (0), same flight-buildable outcome as with resumption
 * disabled. This is the regression guard: sdrv_ch_take_psk must be a true
 * no-op on this path. */
static void test_sdrv_psk_absent_leaves_full_handshake_unchanged(void) {
  sdrv_psk_fixture     f;
  quic_sdrv            s;
  u8                   srv_priv[32], srv_pub[32], cert_priv[32];
  u8                   sh[256], flight[2048];
  quic_obuf            sh_ob, fl_ob;
  quic_sdrv_flight_out fo;
  sdrv_psk_fixture_init(&f);
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_priv[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);
  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, cert_priv, 0,
                            0,        0,       0,         f.ticket_key};
    quic_sdrv_init(&s, &in);
  }
  CHECK(quic_sdrv_recv_client_hello(&s, f.ch, f.ch_len));
  CHECK(s.psk_accepted == 0);
  sh_ob = quic_obuf_of(sh, sizeof(sh));
  fl_ob = quic_obuf_of(flight, sizeof(flight));
  fo    = (quic_sdrv_flight_out){&sh_ob, &fl_ob};
  CHECK(quic_sdrv_build_server_flight(&s, f.srv_random, &fo));
}

/* A valid ticket with a correctly computed binder is accepted --
 * psk_accepted set, psk_secret recorded, and the flight still builds (the
 * PSK-branch key schedule in sdrv_flight.c's derive_secret runs end to end).
 */
static void test_sdrv_psk_valid_ticket_and_binder_accepted(void) {
  sdrv_psk_fixture     f;
  quic_sdrv            s;
  u8                   srv_priv[32], srv_pub[32], cert_priv[32];
  u8                   ch2[700];
  u8                   binder[QUIC_HKDF_PRK];
  usz                  ch2_len, psk_ext_off, trunc_len;
  u8                   sh[256], flight[2048];
  quic_obuf            sh_ob, fl_ob;
  quic_sdrv_flight_out fo;
  sdrv_psk_fixture_init(&f);
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_priv[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);

  /* Placeholder binder first, to learn the extension's own offset and the
   * truncation length -- pre_shared_key's wire size does not depend on the
   * binder's content, only its length (fixed at QUIC_HKDF_PRK here), so the
   * offsets computed from this placeholder pass are exactly the ones the
   * real binder (computed below) will also occupy. */
  {
    u8                 zero_binder[QUIC_HKDF_PRK] = {0};
    quic_tlsext_psk_in psk                        = {
        quic_span_of(f.sealed, sizeof(f.sealed)), 0,
        quic_span_of(zero_binder, sizeof(zero_binder))};
    ch2_len = sdrv_test_append_psk(
        ch2, sizeof(ch2), f.ch, f.ch_len, &psk, &psk_ext_off);
    CHECK(ch2_len != 0);
  }
  trunc_len = sdrv_test_psk_truncate_len(psk_ext_off, sizeof(f.sealed));
  quic_tls_binder_compute(f.psk, quic_span_of(ch2, trunc_len), binder);
  {
    quic_tlsext_psk_in psk = {
        quic_span_of(f.sealed, sizeof(f.sealed)), 0,
        quic_span_of(binder, sizeof(binder))};
    ch2_len = sdrv_test_append_psk(
        ch2, sizeof(ch2), f.ch, f.ch_len, &psk, &psk_ext_off);
    CHECK(ch2_len != 0);
  }

  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, cert_priv, 0,
                            0,        0,       0,         f.ticket_key};
    quic_sdrv_init(&s, &in);
  }
  CHECK(quic_sdrv_recv_client_hello(&s, ch2, ch2_len));
  CHECK(s.psk_accepted == 1);
  for (usz i = 0; i < 32; i++) CHECK(s.psk_secret[i] == f.psk[i]);
  sh_ob = quic_obuf_of(sh, sizeof(sh));
  fl_ob = quic_obuf_of(flight, sizeof(flight));
  fo    = (quic_sdrv_flight_out){&sh_ob, &fl_ob};
  CHECK(quic_sdrv_build_server_flight(&s, f.srv_random, &fo));
}

/* Build a ClientHello carrying early_data + pre_shared_key (a real binder
 * over the correct truncation), returning the accepted-PSK setup shared by
 * the 0-RTT accept/replay tests below. */
static usz sdrv_test_0rtt_ch(
    sdrv_psk_fixture* f, u8* ch2, usz ch2_cap, usz* psk_ext_off) {
  usz ch2_len;
  u8  binder[QUIC_HKDF_PRK];
  usz trunc_len;
  {
    u8                 zero_binder[QUIC_HKDF_PRK] = {0};
    quic_tlsext_psk_in psk                        = {
        quic_span_of(f->sealed, sizeof(f->sealed)), 0,
        quic_span_of(zero_binder, sizeof(zero_binder))};
    ch2_len = sdrv_test_append_early_data_then_psk(
        ch2, ch2_cap, f->ch, f->ch_len, &psk, psk_ext_off);
    if (ch2_len == 0) return 0;
  }
  trunc_len = sdrv_test_psk_truncate_len(*psk_ext_off, sizeof(f->sealed));
  quic_tls_binder_compute(f->psk, quic_span_of(ch2, trunc_len), binder);
  {
    quic_tlsext_psk_in psk = {
        quic_span_of(f->sealed, sizeof(f->sealed)), 0,
        quic_span_of(binder, sizeof(binder))};
    ch2_len = sdrv_test_append_early_data_then_psk(
        ch2, ch2_cap, f->ch, f->ch_len, &psk, psk_ext_off);
  }
  return ch2_len;
}

/* A ClientHello offering both pre_shared_key (accepted, first use) and
 * early_data derives 0-RTT keys matching an independent quic_tls_early_keys
 * computation over the same PSK/ClientHello bytes -- the exact material a
 * peer's own 0-RTT sender would derive (RFC 8446 4.2.10 / RFC 9001 4.6.1). */
static void test_sdrv_early_data_accepted_derives_keys(void) {
  sdrv_psk_fixture  f;
  quic_sdrv         s;
  u8                srv_priv[32], srv_pub[32], cert_priv[32];
  u8                ch2[700];
  usz               ch2_len, psk_ext_off;
  quic_initial_keys want, got;
  sdrv_psk_fixture_init(&f);
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_priv[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);
  ch2_len = sdrv_test_0rtt_ch(&f, ch2, sizeof(ch2), &psk_ext_off);
  CHECK(ch2_len != 0);

  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, cert_priv, 0,
                            0,        0,       0,         f.ticket_key};
    quic_sdrv_init(&s, &in);
  }
  CHECK(quic_sdrv_recv_client_hello(&s, ch2, ch2_len));
  CHECK(s.psk_accepted == 1);
  CHECK(s.early_data_accepted == 1);
  quic_tls_early_keys(f.psk, ch2, ch2_len, &want);
  CHECK(quic_sdrv_early_keys(&s, &got) == 1);
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(got.key[i] == want.key[i]);
  for (usz i = 0; i < QUIC_INITIAL_IV; i++) CHECK(got.iv[i] == want.iv[i]);
  for (usz i = 0; i < QUIC_INITIAL_HP; i++) CHECK(got.hp[i] == want.hp[i]);
}

/* pre_shared_key accepted but no early_data extension -- ordinary PSK
 * resumption without 0-RTT, early_data_accepted stays 0 and no keys are
 * available. */
static void test_sdrv_psk_without_early_data_no_0rtt(void) {
  sdrv_psk_fixture  f;
  quic_sdrv         s;
  u8                srv_priv[32], srv_pub[32], cert_priv[32];
  u8                ch2[700];
  u8                binder[QUIC_HKDF_PRK];
  usz               ch2_len, psk_ext_off, trunc_len;
  quic_initial_keys got;
  sdrv_psk_fixture_init(&f);
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_priv[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);
  {
    u8                 zero_binder[QUIC_HKDF_PRK] = {0};
    quic_tlsext_psk_in psk                        = {
        quic_span_of(f.sealed, sizeof(f.sealed)), 0,
        quic_span_of(zero_binder, sizeof(zero_binder))};
    ch2_len = sdrv_test_append_psk(
        ch2, sizeof(ch2), f.ch, f.ch_len, &psk, &psk_ext_off);
    CHECK(ch2_len != 0);
  }
  trunc_len = sdrv_test_psk_truncate_len(psk_ext_off, sizeof(f.sealed));
  quic_tls_binder_compute(f.psk, quic_span_of(ch2, trunc_len), binder);
  {
    quic_tlsext_psk_in psk = {
        quic_span_of(f.sealed, sizeof(f.sealed)), 0,
        quic_span_of(binder, sizeof(binder))};
    ch2_len = sdrv_test_append_psk(
        ch2, sizeof(ch2), f.ch, f.ch_len, &psk, &psk_ext_off);
    CHECK(ch2_len != 0);
  }
  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, cert_priv, 0,
                            0,        0,       0,         f.ticket_key};
    quic_sdrv_init(&s, &in);
  }
  CHECK(quic_sdrv_recv_client_hello(&s, ch2, ch2_len));
  CHECK(s.psk_accepted == 1);
  CHECK(s.early_data_accepted == 0);
  CHECK(quic_sdrv_early_keys(&s, &got) == 0);
}

/* Presenting the SAME ticket's pre_shared_key+early_data a second time
 * (a replayed 0-RTT ClientHello, e.g. a retransmission-turned-duplicate
 * attempt) is refused for 0-RTT on its second use even though the PSK/binder
 * are still valid -- RFC 8446 8.1 single-use ticket enforcement. PSK-only
 * (non-0-RTT) resumption still proceeds; only early_data is rejected. */
static void test_sdrv_early_data_replay_rejected(void) {
  sdrv_psk_fixture f;
  quic_sdrv        s1, s2;
  u8               srv_priv[32], srv_pub[32], cert_priv[32];
  u8               ch2[700];
  usz              ch2_len, psk_ext_off;
  sdrv_psk_fixture_init(&f);
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_priv[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);
  ch2_len = sdrv_test_0rtt_ch(&f, ch2, sizeof(ch2), &psk_ext_off);
  CHECK(ch2_len != 0);

  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, cert_priv, 0,
                            0,        0,       0,         f.ticket_key};
    quic_sdrv_init(&s1, &in);
  }
  CHECK(quic_sdrv_recv_client_hello(&s1, ch2, ch2_len));
  CHECK(s1.psk_accepted == 1);
  CHECK(s1.early_data_accepted == 1);

  /* The identical ClientHello bytes (same sealed ticket identity) presented
   * again on a fresh driver instance -- the tracker is process-wide, not
   * per-connection, so this simulates a second connection attempt replaying
   * the same 0-RTT flight. */
  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, cert_priv, 0,
                            0,        0,       0,         f.ticket_key};
    quic_sdrv_init(&s2, &in);
  }
  CHECK(quic_sdrv_recv_client_hello(&s2, ch2, ch2_len));
  CHECK(s2.psk_accepted == 1);        /* PSK/1-RTT resumption still allowed */
  CHECK(s2.early_data_accepted == 0); /* 0-RTT itself is refused */
}

/* A garbage/wrong-key identity fails to open as a ticket -- graceful
 * fallback to a full handshake (RFC 8446 4.2.11 MAY), never a hard failure.
 * The binder bytes are irrelevant here since the ticket never opens. */
static void test_sdrv_psk_ticket_open_fails_falls_back(void) {
  sdrv_psk_fixture f;
  quic_sdrv        s;
  u8               srv_priv[32], srv_pub[32], cert_priv[32];
  u8               ch2[700];
  u8               garbage[QUIC_TICKET_SEALED_LEN];
  u8               binder[QUIC_HKDF_PRK] = {0};
  usz              ch2_len, psk_ext_off;
  sdrv_psk_fixture_init(&f);
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_priv[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);
  for (usz i = 0; i < sizeof(garbage); i++) garbage[i] = (u8)(0xee ^ i);

  {
    quic_tlsext_psk_in psk = {
        quic_span_of(garbage, sizeof(garbage)), 0,
        quic_span_of(binder, sizeof(binder))};
    ch2_len = sdrv_test_append_psk(
        ch2, sizeof(ch2), f.ch, f.ch_len, &psk, &psk_ext_off);
    CHECK(ch2_len != 0);
  }
  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, cert_priv, 0,
                            0,        0,       0,         f.ticket_key};
    quic_sdrv_init(&s, &in);
  }
  CHECK(quic_sdrv_recv_client_hello(&s, ch2, ch2_len));
  CHECK(s.psk_accepted == 0);
}

/* RFC 8446 4.2.11.2: a ticket that opens but whose binder does not match MUST
 * abort the handshake -- quic_sdrv_recv_client_hello must return 0, not fall
 * back to a full handshake as if nothing had been offered. */
static void test_sdrv_psk_binder_mismatch_aborts(void) {
  sdrv_psk_fixture f;
  quic_sdrv        s;
  u8               srv_priv[32], srv_pub[32], cert_priv[32];
  u8               ch2[700];
  u8               wrong_binder[QUIC_HKDF_PRK];
  usz              ch2_len, psk_ext_off;
  sdrv_psk_fixture_init(&f);
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_priv[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);
  for (usz i = 0; i < sizeof(wrong_binder); i++)
    wrong_binder[i] = (u8)(0x11 + i);

  {
    quic_tlsext_psk_in psk = {
        quic_span_of(f.sealed, sizeof(f.sealed)), 0,
        quic_span_of(wrong_binder, sizeof(wrong_binder))};
    ch2_len = sdrv_test_append_psk(
        ch2, sizeof(ch2), f.ch, f.ch_len, &psk, &psk_ext_off);
    CHECK(ch2_len != 0);
  }
  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, cert_priv, 0,
                            0,        0,       0,         f.ticket_key};
    quic_sdrv_init(&s, &in);
  }
  CHECK(!quic_sdrv_recv_client_hello(&s, ch2, ch2_len));
}

/* RFC 8446 4.2.11.2: a correctly computed binder, but the transcript is
 * tampered (one byte of ClientHello.random flipped) between binder computation
 * and verification -- this exercises binder.c's own tamper detection through
 * the real wire-parsing path (sdrv_psk_truncate's slice), not just binder.c's
 * isolated unit tests. Must abort exactly like an outright wrong binder. */
static void test_sdrv_psk_tampered_transcript_aborts(void) {
  sdrv_psk_fixture f;
  quic_sdrv        s;
  u8               srv_priv[32], srv_pub[32], cert_priv[32];
  u8               ch2[700];
  u8               binder[QUIC_HKDF_PRK];
  usz              ch2_len, psk_ext_off, trunc_len;
  sdrv_psk_fixture_init(&f);
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_priv[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);

  {
    u8                 zero_binder[QUIC_HKDF_PRK] = {0};
    quic_tlsext_psk_in psk                        = {
        quic_span_of(f.sealed, sizeof(f.sealed)), 0,
        quic_span_of(zero_binder, sizeof(zero_binder))};
    ch2_len = sdrv_test_append_psk(
        ch2, sizeof(ch2), f.ch, f.ch_len, &psk, &psk_ext_off);
    CHECK(ch2_len != 0);
  }
  trunc_len = sdrv_test_psk_truncate_len(psk_ext_off, sizeof(f.sealed));
  quic_tls_binder_compute(f.psk, quic_span_of(ch2, trunc_len), binder);
  {
    quic_tlsext_psk_in psk = {
        quic_span_of(f.sealed, sizeof(f.sealed)), 0,
        quic_span_of(binder, sizeof(binder))};
    ch2_len = sdrv_test_append_psk(
        ch2, sizeof(ch2), f.ch, f.ch_len, &psk, &psk_ext_off);
    CHECK(ch2_len != 0);
  }
  /* Flip a byte inside ClientHello.random (offset 4+2), well before the
   * pre_shared_key extension, after the binder was already computed over
   * the untampered bytes. */
  ch2[6] ^= 0x01;

  {
    quic_sdrv_init_in in = {srv_priv, srv_pub, cert_priv, 0,
                            0,        0,       0,         f.ticket_key};
    quic_sdrv_init(&s, &in);
  }
  CHECK(!quic_sdrv_recv_client_hello(&s, ch2, ch2_len));
}

void test_sdrv(void) {
  test_sdrv_keyshare_walk_rejects_overclaimed_exts_len();
  test_sdrv_tp_walk_rejects_overclaimed_exts_len();
  test_sdrv_keyshare_walk_rejects_overclaimed_ext_payload_len();
  test_sdrv_keyshare_walk_accepts_exact_exts_len();
  test_sdrv_recv_client_hello_stores_peer_max_datagram_frame_size();
  test_sdrv_recv_client_hello_no_max_datagram_param_stays_zero();
  test_sdrv_recv_client_hello_no_tp_ext_stays_zero();
  test_sdrv_recv_client_hello_tp_ext_present_ok();
  test_sdrv_recv_client_hello_missing_tp_ext_rejected();
  test_sdrv_recv_client_hello_dup_tp_rejected();
  test_sdrv_recv_client_hello_stores_peer_initial_max_data();
  test_sdrv_recv_client_hello_no_initial_max_data_stays_zero();
  test_sdrv_recv_client_hello_stores_peer_initial_max_stream_data_bidi_local();
  test_sdrv_recv_client_hello_no_initial_max_stream_data_bidi_local_stays_zero();
  test_sdrv_recv_client_hello_stores_peer_initial_max_stream_data_bidi_remote();
  test_sdrv_recv_client_hello_stores_peer_initial_max_stream_data_uni();
  test_sdrv_recv_client_hello_no_server_initiated_stream_credit_stays_zero();
  test_sdrv_session_id_echo();
  test_sdrv_external_chain();
  test_sdrv_external_chain_wrong_key();
  test_sdrv_chain_overflow();
  test_sdrv_flight_nine_cert_chain();
  test_sdrv_suite_aes_only();
  test_sdrv_suite_chacha_only();
  test_sdrv_suite_prefers_aes();
  test_sdrv_suite_no_overlap_fails();
  test_sdrv_suite_malformed_vec();
  test_sdrv_suite_vec_overruns_body();
  test_sdrv_retry_advertises_true_odcid_not_key_derivation_dcid();
  test_sdrv_psk_absent_leaves_full_handshake_unchanged();
  test_sdrv_psk_valid_ticket_and_binder_accepted();
  test_sdrv_psk_ticket_open_fails_falls_back();
  test_sdrv_psk_binder_mismatch_aborts();
  test_sdrv_psk_tampered_transcript_aborts();
  test_sdrv_early_data_accepted_derives_keys();
  test_sdrv_psk_without_early_data_no_0rtt();
  test_sdrv_early_data_replay_rejected();

  u8 cli_priv[32], cli_pub[32], srv_priv[32], srv_pub[32];
  u8 cert_priv[32];
  u8 ch[512], sh[256], flight[2048];
  u8 srv_random[32], shared_cli[32], hs[32], s_traffic[32], th[32];
  u8 sh_pub[32];
  quic_serverhello_out shout;
  usz                  ch_len, sh_len, hs_len, p = 0;
  const u8 *           ee, *cm, *cv, *fin, *srv_hs_secret;
  usz                  eel, cml, cvl, finl;
  u16                  cv_scheme;
  quic_span            cv_sig;
  quic_sdrv            s;

  for (usz i = 0; i < 32; i++) {
    cli_priv[i]   = (u8)(i + 1);
    srv_priv[i]   = (u8)(0x40 + i);
    cert_priv[i]  = (u8)(0x80 + i);
    srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, cli_priv);
  quic_x25519_base(srv_pub, srv_priv);

  /* client: emit a ClientHello carrying its x25519 key_share. */
  ch_len = quic_tls_client_hello(
      &(quic_clienthello_in){
          srv_random, cli_pub, quic_span_of(0, 0), quic_span_of(0, 0)},
      &(quic_obuf){ch, sizeof(ch), 0});
  CHECK(ch_len != 0);

  /* server: drive the flight (the driver builds its own P-256 cert). */
  {
    quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0, 0, 0};
    quic_sdrv_init(&s, &din);
  }
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  {
    quic_obuf            sh_ob = quic_obuf_of(sh, sizeof(sh));
    quic_obuf            fl_ob = quic_obuf_of(flight, sizeof(flight));
    quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
    CHECK(quic_sdrv_build_server_flight(&s, srv_random, &fo));
    sh_len = sh_ob.len;
    hs_len = fl_ob.len;
  }

  /* client: parse ServerHello and reach the same ECDHE shared secret. */
  CHECK(quic_tls_parse_server_hello(quic_span_of(sh, sh_len), sh_pub, &shout));
  CHECK(shout.cipher == 0x1301);
  CHECK(shout.version == 0x0304);
  quic_x25519(shared_cli, cli_priv, sh_pub);

  /* both derive the same handshake secret from the shared ECDHE. */
  quic_tls_handshake_secret(shared_cli, hs);
  CHECK(quic_sdrv_handshake_secret(&s, &srv_hs_secret));
  for (usz i = 0; i < 32; i++) CHECK(hs[i] == srv_hs_secret[i]);

  /* split the flight into its four messages. */
  CHECK(next_hs(flight, hs_len, &p, &ee, &eel));
  CHECK(next_hs(flight, hs_len, &p, &cm, &cml));
  CHECK(next_hs(flight, hs_len, &p, &cv, &cvl));
  CHECK(next_hs(flight, hs_len, &p, &fin, &finl));
  CHECK(ee[0] == 0x08 && cm[0] == 0x0b && cv[0] == 0x0f && fin[0] == 0x14);

  /* RFC 5480 / RFC 5280 4.1.2.7: the end-entity certificate the server put on
   * the wire is structurally an ECDSA P-256 cert (id-ecPublicKey SPKI carrying
   * an uncompressed secp256r1 point), not Ed25519. This is what BoringSSL
   * (curl/quiche) requires; prove it from the Certificate message bytes. */
  {
    quic_x509           crt;
    quic_tls_cert_entry ee_cert;
    quic_span           ctx;
    quic_span           alg_oid, spki_key;
    u8                  px[32], py[32];
    CHECK(quic_tls_cert_parse(quic_span_of(cm + 4, cml - 4), &ctx, &ee_cert));
    CHECK(quic_x509_parse(
        quic_span_of(ee_cert.cert_data, ee_cert.cert_len), &crt));
    CHECK(quic_x509_public_key(crt.tbs, &alg_oid, &spki_key));
    CHECK(quic_x509_is_ec(alg_oid) == 1);
    CHECK(quic_x509_ec_pubkey(spki_key, px, py) == 1);
  }

  /* CertificateVerify verifies against the server's self-built P-256
   * certificate over the transcript through Certificate. */
  {
    quic_transcript tr;
    quic_transcript_init(&tr);
    quic_transcript_add(&tr, ch, ch_len);
    quic_transcript_add(&tr, sh, sh_len);
    quic_transcript_add(&tr, ee, eel);
    quic_transcript_add(&tr, cm, cml);
    quic_transcript_hash(&tr, th);
  }
  CHECK(quic_tls_certverify_parse(
      quic_span_of(cv + 4, cvl - 4), &cv_scheme, &cv_sig));
  CHECK(cv_scheme == 0x0403);
  {
    quic_certverify_in cvin;
    cvin.scheme          = 0x0403;
    cvin.cert            = s.certs[0];
    cvin.sig             = cv_sig;
    cvin.transcript_hash = th;
    CHECK(quic_tls_verify_cert_signature(&cvin));
  }

  /* RFC 9000 7.3: the EncryptedExtensions transport parameters carry the real
   * ODCID (client first Initial DCID) and ISCID (server SCID), not empty cids.
   * EE = header(4) + ext_list_len(2) + ALPN(9), then the 0x39 ext. */
  {
    static const u8 client_dcid[] = {0x83, 0x94, 0xc8, 0xf0,
                                     0x3e, 0x51, 0x57, 0x08};
    static const u8 server_scid[] = {0x11, 0x22, 0x33, 0x44, 0x55};
    u8              ch2[512], sh2[256], flight2[2048];
    usz             hs2_len, q = 0;
    const u8*       ee2;
    usz             ee2l;
    quic_span       tp, cid;
    quic_stp_out    cido = {0, &cid};
    quic_sdrv       s2;

    {
      quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0, 0, 0};
      quic_sdrv_init(&s2, &din);
    }
    CHECK(quic_sdrv_set_cids(
        &s2, quic_span_of(client_dcid, sizeof(client_dcid)),
        quic_span_of(server_scid, sizeof(server_scid))));
    /* Opting in to DATAGRAM support (RFC 9221 3) makes the real server
     * flight advertise a non-zero max_datagram_frame_size, not just the
     * isolated codec. */
    s2.limits.max_datagram_frame_size = 65535;
    ch_len                            = quic_tls_client_hello(
        &(quic_clienthello_in){
            srv_random, cli_pub, quic_span_of(0, 0), quic_span_of(0, 0)},
        &(quic_obuf){ch2, sizeof(ch2), 0});
    CHECK(quic_sdrv_recv_client_hello(&s2, ch2, ch_len));
    {
      quic_obuf            sh_ob = quic_obuf_of(sh2, sizeof(sh2));
      quic_obuf            fl_ob = quic_obuf_of(flight2, sizeof(flight2));
      quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
      CHECK(quic_sdrv_build_server_flight(&s2, srv_random, &fo));
      hs2_len = fl_ob.len;
    }
    CHECK(next_hs(flight2, hs2_len, &q, &ee2, &ee2l));
    CHECK(quic_tpext_decode(quic_span_of(ee2 + 15, ee2l - 15), &tp) != 0);

    CHECK(
        quic_stp_parse(tp, QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, &cido) ==
        1);
    CHECK(
        cid.n == sizeof(client_dcid) &&
        quic_tparam_cid_match(
            cid, quic_span_of(client_dcid, sizeof(client_dcid))));
    CHECK(quic_stp_parse(tp, QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, &cido) == 1);
    CHECK(
        cid.n == sizeof(server_scid) &&
        quic_tparam_cid_match(
            cid, quic_span_of(server_scid, sizeof(server_scid))));

    /* The real flight's transport parameters carry the opted-in
     * max_datagram_frame_size (0x20), not zero/absent. */
    {
      u64          dgram_size = 0;
      quic_stp_out dgo        = {&dgram_size, 0};
      CHECK(quic_stp_parse(tp, QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, &dgo) == 1);
      CHECK(dgram_size == 65535);
    }
  }

  /* Finished verifies under the server handshake traffic secret (derived
   * over the transcript through ServerHello) at the transcript hash through
   * CertificateVerify. */
  {
    quic_transcript tr;
    u8              fin_th[32];
    quic_transcript_init(&tr);
    quic_transcript_add(&tr, ch, ch_len);
    quic_transcript_add(&tr, sh, sh_len);
    quic_transcript_hash(&tr, fin_th); /* through ServerHello */
    quic_hkdf_label shl = {"s hs traffic", 12, {fin_th, 32}};
    quic_hkdf_expand_label(hs, &shl, quic_mspan_of(s_traffic, 32));
    quic_transcript_add(&tr, ee, eel);
    quic_transcript_add(&tr, cm, cml);
    quic_transcript_add(&tr, cv, cvl);
    quic_transcript_hash(&tr, fin_th); /* through CertificateVerify */
    CHECK(quic_tls_finished_check(s_traffic, fin_th, fin + 4));
  }
}
