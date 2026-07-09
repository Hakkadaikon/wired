#include "tls/handshake/core/sdrv/sdrv.h"

#include <stdlib.h> /* malloc/free: hosted test build only, see test.h */

#include "app/datagram/datagram/datagram.h"
#include "crypto/pki/encoding/x509/ec_pubkey.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/castore.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "realchain_golden.h"
#include "test.h"
#include "tls/ext/stp/parse_tp.h"
#include "tls/ext/tparam/tparam.h"
#include "tls/ext/tparam/tpcheck.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tls/certverify.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/serverhello.h"
#include "tls/handshake/core/tls/tpext.h"
#include "tls/handshake/core/tls/x25519.h"

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

  {
    static const u8 tp[1] = {0};
    ch_len                = quic_tls_client_hello(
        &(quic_clienthello_in){
            srv_random, cli_pub, quic_span_of(0, 0),
            quic_span_of(tp, sizeof(tp))},
        &(quic_obuf){ch, sizeof(ch), 0});
  }
  CHECK(ch_len != 0);
  ch2_len = ch_with_sid(ch2, ch, ch_len, sid);

  {
    quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0};
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
    quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0};
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

/* Build a ClientHello with a real x25519 key_share, sized for the caller. */
static usz sdrv_test_client_hello(
    u8* ch, usz ch_cap, const u8* cli_pub, const u8* srv_random) {
  static const u8 tp[1] = {0};
  return quic_tls_client_hello(
      &(quic_clienthello_in){
          srv_random, cli_pub, quic_span_of(0, 0), quic_span_of(tp, 1)},
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
    quic_sdrv_init_in in = {srv_priv, srv_pub, quic_realchain_leaf_priv,
                            chain,    2,       0};
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
    quic_sdrv_init_in in = {srv_priv, srv_pub, wrong_priv, chain, 2, 0};
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

/* chain_count over QUIC_TLS_CERT_CHAIN_MAX fails the flight closed: nothing
 * to send, quic_sdrv_build_server_flight returns 0. */
static void test_sdrv_chain_overflow(void) {
  u8        cli_priv[32], cli_pub[32], srv_priv[32], srv_pub[32];
  u8        cert_priv[32];
  u8        ch[512], sh[256], flight[2048], srv_random[32];
  usz       ch_len;
  quic_sdrv s;
  quic_span chain[5] = {
      quic_span_of(quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der)),
      quic_span_of(quic_realchain_int_der, sizeof(quic_realchain_int_der)),
      quic_span_of(quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der)),
      quic_span_of(quic_realchain_int_der, sizeof(quic_realchain_int_der)),
      quic_span_of(quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der))};

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
    quic_sdrv_init_in    in    = {srv_priv, srv_pub, cert_priv, chain, 5, 0};
    quic_obuf            sh_ob = quic_obuf_of(sh, sizeof(sh));
    quic_obuf            fl_ob = quic_obuf_of(flight, sizeof(flight));
    quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
    quic_sdrv_init(&s, &in);
    CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
    CHECK(!quic_sdrv_build_server_flight(&s, srv_random, &fo));
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
    quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0};
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
    quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0};
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

void test_sdrv(void) {
  test_sdrv_keyshare_walk_rejects_overclaimed_exts_len();
  test_sdrv_tp_walk_rejects_overclaimed_exts_len();
  test_sdrv_keyshare_walk_rejects_overclaimed_ext_payload_len();
  test_sdrv_keyshare_walk_accepts_exact_exts_len();
  test_sdrv_recv_client_hello_stores_peer_max_datagram_frame_size();
  test_sdrv_recv_client_hello_no_max_datagram_param_stays_zero();
  test_sdrv_recv_client_hello_no_tp_ext_stays_zero();
  test_sdrv_session_id_echo();
  test_sdrv_external_chain();
  test_sdrv_external_chain_wrong_key();
  test_sdrv_chain_overflow();

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
  {
    static const u8 tp[1] = {0};
    ch_len                = quic_tls_client_hello(
        &(quic_clienthello_in){
            srv_random, cli_pub, quic_span_of(0, 0),
            quic_span_of(tp, sizeof(tp))},
        &(quic_obuf){ch, sizeof(ch), 0});
  }
  CHECK(ch_len != 0);

  /* server: drive the flight (the driver builds its own P-256 cert). */
  {
    quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0};
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
      quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0};
      quic_sdrv_init(&s2, &din);
    }
    CHECK(quic_sdrv_set_cids(
        &s2, quic_span_of(client_dcid, sizeof(client_dcid)),
        quic_span_of(server_scid, sizeof(server_scid))));
    /* WT-A-006: opting in to DATAGRAM support (RFC 9221 3) makes the real
     * server flight advertise a non-zero max_datagram_frame_size, not just
     * the isolated codec. */
    s2.limits.max_datagram_frame_size = 65535;
    ch_len                            = quic_tls_client_hello(
        &(quic_clienthello_in){
            srv_random, cli_pub, quic_span_of(0, 0),
            quic_span_of((const u8*)"\0", 1)},
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

    /* WT-A-006: the real flight's transport parameters carry the opted-in
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
