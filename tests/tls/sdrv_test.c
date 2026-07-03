#include "tls/handshake/core/sdrv/sdrv.h"

#include "crypto/pki/encoding/x509/ec_pubkey.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
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
static int next_hs(const u8 *b, usz n, usz *p, const u8 **msg, usz *len) {
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
static usz ch_with_sid(u8 *out, const u8 *ch, usz ch_len, const u8 sid[32]) {
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
            srv_random, cli_pub, quic_span_of(0, 0), quic_span_of(tp, sizeof(tp))},
        &(quic_obuf){ch, sizeof(ch), 0});
  }
  CHECK(ch_len != 0);
  ch2_len = ch_with_sid(ch2, ch, ch_len, sid);

  quic_sdrv_init(&s, srv_priv, srv_pub, cert_priv, 0, 0);
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
  quic_sdrv_init(&s, srv_priv, srv_pub, cert_priv, 0, 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
  {
    quic_obuf            sh_ob = quic_obuf_of(sh, sizeof(sh));
    quic_obuf            fl_ob = quic_obuf_of(flight, sizeof(flight));
    quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
    CHECK(quic_sdrv_build_server_flight(&s, srv_random, &fo));
  }
  CHECK(sh[38] == 0);
}

void test_sdrv(void) {
  test_sdrv_session_id_echo();

  u8        cli_priv[32], cli_pub[32], srv_priv[32], srv_pub[32];
  u8        cert_priv[32];
  u8        ch[512], sh[256], flight[2048];
  u8        srv_random[32], shared_cli[32], hs[32], s_traffic[32], th[32];
  u8                   sh_pub[32];
  quic_serverhello_out shout;
  usz       ch_len, sh_len, hs_len, p = 0;
  const u8 *ee, *cm, *cv, *fin, *srv_hs_secret;
  usz       eel, cml, cvl, finl;
  u16       cv_scheme;
  quic_span cv_sig;
  quic_sdrv s;

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
            srv_random, cli_pub, quic_span_of(0, 0), quic_span_of(tp, sizeof(tp))},
        &(quic_obuf){ch, sizeof(ch), 0});
  }
  CHECK(ch_len != 0);

  /* server: drive the flight (the driver builds its own P-256 cert). */
  quic_sdrv_init(&s, srv_priv, srv_pub, cert_priv, 0, 0);
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
    cvin.cert            = quic_span_of(s.cert_der, s.cert_len);
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
    const u8       *ee2;
    usz             ee2l;
    quic_span       tp, cid;
    quic_stp_out    cido = {0, &cid};
    quic_sdrv       s2;

    quic_sdrv_init(&s2, srv_priv, srv_pub, cert_priv, 0, 0);
    CHECK(quic_sdrv_set_cids(
        &s2, quic_span_of(client_dcid, sizeof(client_dcid)),
        quic_span_of(server_scid, sizeof(server_scid))));
    ch_len = quic_tls_client_hello(
        &(quic_clienthello_in){
            srv_random, cli_pub, quic_span_of(0, 0),
            quic_span_of((const u8 *)"\0", 1)},
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
    CHECK(
        quic_stp_parse(tp, QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, &cido) == 1);
    CHECK(
        cid.n == sizeof(server_scid) &&
        quic_tparam_cid_match(
            cid, quic_span_of(server_scid, sizeof(server_scid))));
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
