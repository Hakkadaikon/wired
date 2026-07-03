#include "tls/handshake/roles/client/client.h"

#include "crypto/asymmetric/ecc/p256sign/sign.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "fullhs_golden.h"
#include "realchain_golden.h"
#include "test.h"
#include "tls/handshake/core/tls/certverify.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/hsdriver.h"
#include "tls/handshake/core/tls/x25519.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

/* Minimal ServerHello (RFC 8446 4.1.3) carrying an x25519 key_share pub. */
static usz client_build_sh(u8 *out, usz cap, const u8 pub[32]) {
  usz off      = quic_hs_begin(out, cap, 2), block;
  out[off]     = 0x03;
  out[off + 1] = 0x03;
  for (usz i = 0; i < 32; i++) out[off + 2 + i] = (u8)(0x10 + i);
  out[off + 34] = 0;
  out[off + 35] = 0x13;
  out[off + 36] = 0x01;
  out[off + 37] = 0;
  block         = off + 38;
  off           = block + 2;
  out[off]      = 0x00;
  out[off + 1]  = 0x2b;
  out[off + 2]  = 0x00;
  out[off + 3]  = 2;
  out[off + 4]  = 0x03;
  out[off + 5]  = 0x04;
  off += 6;
  out[off]     = 0x00;
  out[off + 1] = 0x33;
  out[off + 2] = 0x00;
  out[off + 3] = 36;
  out[off + 4] = 0x00;
  out[off + 5] = 0x1d;
  out[off + 6] = 0x00;
  out[off + 7] = 32;
  for (usz i = 0; i < 32; i++) out[off + 8 + i] = pub[i];
  off += 40;
  out[block]     = (u8)((off - block - 2) >> 8);
  out[block + 1] = (u8)(off - block - 2);
  quic_hs_finish(out, off);
  (void)cap;
  return off;
}

/* CertificateVerify: type(15) len(3) | scheme(2) | sig(2+len). */
static usz client_build_cv(u8 *out, u16 scheme, const u8 *sig, usz sig_len) {
  usz body = 4 + sig_len;
  out[0]   = 0x0f;
  out[1]   = 0;
  out[2]   = (u8)(body >> 8);
  out[3]   = (u8)body;
  out[4]   = (u8)(scheme >> 8);
  out[5]   = (u8)scheme;
  out[6]   = (u8)(sig_len >> 8);
  out[7]   = (u8)sig_len;
  for (usz i = 0; i < sig_len; i++) out[8 + i] = sig[i];
  return 4 + body;
}

/* Drive a client tlsdriver and a server tlsdriver to the shared handshake
 * secret over real ECDHE (mirror of the on-wire CH/SH exchange). */
static void client_reach_hs_secret(
    quic_tlsdriver *cl, quic_tlsdriver *sv, const u8 sv_pub[32]) {
  u8  frame[1024], sh[256];
  usz fl, shn;
  {
    quic_obuf ob = quic_obuf_of(frame, sizeof(frame));
    CHECK(quic_tlsdriver_client_hello(cl, &ob) == 1);
    fl = ob.len;
  }
  CHECK(quic_tlsdriver_recv_crypto(sv, frame, fl) == 1);
  shn = client_build_sh(sh, sizeof(sh), sv_pub);
  {
    quic_obuf ob = quic_obuf_of(frame, sizeof(frame));
    quic_crypto_stream_emit_in ein = {0, 256};
    CHECK(quic_crypto_stream_emit(quic_span_of(sh, shn), &ein, &ob) == 1);
    fl = ob.len;
  }
  CHECK(quic_tlsdriver_recv_crypto(cl, frame, fl) == 1);
  CHECK(quic_tlsdriver_handshake_secret_ready(cl) == 1);
}

/* RFC 9000 14.1: the Initial built by start is padded to 1200 bytes. */
static void test_client_initial_padded(void) {
  u8          cl_priv[32], cl_pub[32], dg[QUIC_CLIENT_DATAGRAM_MAX];
  quic_client c;
  usz         len;
  for (usz i = 0; i < 32; i++) cl_priv[i] = (u8)(7 + i);
  quic_x25519_base(cl_pub, cl_priv);
  quic_tlsdriver_init(&c.tls, cl_priv, cl_pub, 0);
  len = quic_client_build_initial(&c, dg, sizeof(dg));
  CHECK(len == 1200);
}

/* RFC 9001 4.1: feeding a real ServerHello advances INITIAL -> AUTH. */
static void test_client_feed_serverhello(void) {
  u8 cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32], sh[256], frame[1024];
  quic_client    c;
  quic_tlsdriver svtls;
  usz            shn, fl;

  for (usz i = 0; i < 32; i++) {
    cl_priv[i] = (u8)(1 + i);
    sv_priv[i] = (u8)(200 - i);
  }
  quic_x25519_base(cl_pub, cl_priv);
  quic_x25519_base(sv_pub, sv_priv);
  quic_tlsdriver_init(&c.tls, cl_priv, cl_pub, 0);
  c.phase    = QUIC_CLIENT_HS_INITIAL;
  c.sh_len   = 0;
  c.now      = 0; /* no cert policy: legacy behavior */
  c.host     = 0;
  c.host_len = 0;
  c.castore  = 0;
  quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);
  {
    quic_obuf ob = quic_obuf_of(frame, sizeof(frame));
    CHECK(quic_tlsdriver_client_hello(&c.tls, &ob) == 1);
    fl = ob.len;
  }
  CHECK(quic_tlsdriver_recv_crypto(&svtls, frame, fl) == 1);

  shn = client_build_sh(sh, sizeof(sh), sv_pub);
  {
    quic_obuf ob = quic_obuf_of(frame, sizeof(frame));
    quic_crypto_stream_emit_in ein = {0, 256};
    CHECK(quic_crypto_stream_emit(quic_span_of(sh, shn), &ein, &ob) == 1);
    fl = ob.len;
  }
  CHECK(quic_client_feed(&c, frame, fl) == 1);
  CHECK(c.phase == QUIC_CLIENT_HS_AUTH);
}

/* RFC 8446 4.4 / RFC 9001 4.1: client_run_handshake reaches confirmed by
 * feeding Certificate, CertificateVerify and the server Finished (no socket).
 */
static void test_client_e2e_confirmed(void) {
  quic_client    c;
  quic_fullhs    sv;
  quic_tlsdriver svtls;
  u8             cv[256], svfin[64];
  u8             cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
  usz            cv_len, n;

  for (usz i = 0; i < 32; i++) {
    cl_priv[i] = (u8)(1 + i);
    sv_priv[i] = (u8)(200 - i);
  }
  quic_x25519_base(cl_pub, cl_priv);
  quic_x25519_base(sv_pub, sv_priv);
  quic_tlsdriver_init(&c.tls, cl_priv, cl_pub, 0);
  quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);

  /* both sides agree the same ECDHE secret, then fix fullhs to the golden
   * transcript so the golden CV/Finished verify on both. */
  client_reach_hs_secret(&c.tls, &svtls, sv_pub);
  CHECK(quic_tlsdriver_handshake_secret_ready(&svtls) == 1);
  CHECK(quic_fullhs_init(&c.hs, &c.tls, quic_span_of(fullhs_sh, sizeof(fullhs_sh))) == 1);
  CHECK(quic_fullhs_init(&sv, &svtls, quic_span_of(fullhs_sh, sizeof(fullhs_sh))) == 1);
  c.phase = QUIC_CLIENT_HS_AUTH;
  c.fd    = -1;

  /* server authenticates itself and signs its Finished. */
  cv_len = client_build_cv(
      cv, QUIC_TLS_SCHEME_ED25519, fullhs_cv_sig, sizeof(fullhs_cv_sig));
  CHECK(
      quic_fullhs_recv_cert(&sv, fullhs_cert_msg, sizeof(fullhs_cert_msg)) ==
      1);
  CHECK(
      quic_fullhs_recv_certverify(&sv, quic_span_of(cv, cv_len), QUIC_TLS_SCHEME_ED25519) ==
      1);
  {
    quic_obuf ob = quic_obuf_of(svfin, sizeof(svfin));
    CHECK(quic_fullhs_send_finished(&sv, &ob) == 1);
    n = ob.len;
  }

  /* client consumes the server's auth flight via feed; reaches confirmed. */
  CHECK(quic_client_feed(&c, fullhs_cert_msg, sizeof(fullhs_cert_msg)) == 1);
  CHECK(quic_client_feed(&c, cv, cv_len) == 1);
  CHECK(quic_client_feed(&c, svfin, n) == 1);
  CHECK(quic_client_is_connected(&c) == 1);
}

/* Shared fixture for the policy tests: a client at INITIAL with the given
 * cert policy, plus a server tlsdriver that consumed our ClientHello, ready
 * for the SH -> Certificate feed sequence. */
static void policy_client(
    quic_client    *c,
    quic_tlsdriver *svtls,
    u64             now,
    const u8       *host,
    usz             host_len) {
  u8  cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32], sh[256], frame[1024];
  usz shn, fl;
  for (usz i = 0; i < 32; i++) {
    cl_priv[i] = (u8)(1 + i);
    sv_priv[i] = (u8)(200 - i);
  }
  quic_x25519_base(cl_pub, cl_priv);
  quic_x25519_base(sv_pub, sv_priv);
  quic_tlsdriver_init(&c->tls, cl_priv, cl_pub, 0);
  c->phase    = QUIC_CLIENT_HS_INITIAL;
  c->sh_len   = 0;
  c->fd       = -1;
  c->now      = now;
  c->host     = host;
  c->host_len = host_len;
  c->castore  = 0;
  quic_tlsdriver_init(svtls, sv_priv, sv_pub, 1);
  {
    quic_obuf ob = quic_obuf_of(frame, sizeof(frame));
    CHECK(quic_tlsdriver_client_hello(&c->tls, &ob) == 1);
    fl = ob.len;
  }
  CHECK(quic_tlsdriver_recv_crypto(svtls, frame, fl) == 1);
  shn = client_build_sh(sh, sizeof(sh), sv_pub);
  {
    quic_obuf ob = quic_obuf_of(frame, sizeof(frame));
    quic_crypto_stream_emit_in ein = {0, 256};
    CHECK(quic_crypto_stream_emit(quic_span_of(sh, shn), &ein, &ob) == 1);
    fl = ob.len;
  }
  CHECK(quic_client_feed(c, frame, fl) == 1); /* injects the policy */
  CHECK(c->phase == QUIC_CLIENT_HS_AUTH);
}

/* RFC 5280 6.1: with an expired clock the Certificate is refused via the
 * feed path and the client can never reach connected. */
static void test_client_expired_now(void) {
  quic_client    c;
  quic_tlsdriver svtls;
  policy_client(&c, &svtls, 20370101000000ULL, 0, 0);
  CHECK(quic_client_feed(&c, fullhs_cert_msg, sizeof(fullhs_cert_msg)) == 0);
  CHECK(quic_client_is_connected(&c) == 0);
}

/* RFC 6125: a hostname that the cert does not name (the golden cert has no
 * SAN) is refused and the client can never reach connected. */
static void test_client_wrong_host(void) {
  quic_client    c;
  quic_tlsdriver svtls;
  policy_client(&c, &svtls, 0, (const u8 *)"other.example", 13);
  CHECK(quic_client_feed(&c, fullhs_cert_msg, sizeof(fullhs_cert_msg)) == 0);
  CHECK(quic_client_is_connected(&c) == 0);
}

/* An in-window clock does not false-positive: the same golden flight as the
 * e2e test still reaches connected with the validity check enforced. */
static void test_client_policy_valid(void) {
  quic_client    c;
  quic_fullhs    sv;
  quic_tlsdriver svtls;
  u8             cv[256], svfin[64];
  u8             cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
  usz            cv_len, n;

  for (usz i = 0; i < 32; i++) {
    cl_priv[i] = (u8)(1 + i);
    sv_priv[i] = (u8)(200 - i);
  }
  quic_x25519_base(cl_pub, cl_priv);
  quic_x25519_base(sv_pub, sv_priv);
  quic_tlsdriver_init(&c.tls, cl_priv, cl_pub, 0);
  quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);
  client_reach_hs_secret(&c.tls, &svtls, sv_pub);
  CHECK(quic_fullhs_init(&c.hs, &c.tls, quic_span_of(fullhs_sh, sizeof(fullhs_sh))) == 1);
  CHECK(quic_fullhs_init(&sv, &svtls, quic_span_of(fullhs_sh, sizeof(fullhs_sh))) == 1);
  /* what feed_initial injects for a client with an in-window clock */
  quic_fullhs_set_policy(&c.hs, 20270101000000ULL, quic_span_of(0, 0));
  c.phase = QUIC_CLIENT_HS_AUTH;
  c.fd    = -1;

  cv_len = client_build_cv(
      cv, QUIC_TLS_SCHEME_ED25519, fullhs_cv_sig, sizeof(fullhs_cv_sig));
  CHECK(
      quic_fullhs_recv_cert(&sv, fullhs_cert_msg, sizeof(fullhs_cert_msg)) ==
      1);
  CHECK(
      quic_fullhs_recv_certverify(&sv, quic_span_of(cv, cv_len), QUIC_TLS_SCHEME_ED25519) ==
      1);
  {
    quic_obuf ob = quic_obuf_of(svfin, sizeof(svfin));
    CHECK(quic_fullhs_send_finished(&sv, &ob) == 1);
    n = ob.len;
  }

  CHECK(quic_client_feed(&c, fullhs_cert_msg, sizeof(fullhs_cert_msg)) == 1);
  CHECK(quic_client_feed(&c, cv, cv_len) == 1);
  CHECK(quic_client_feed(&c, svfin, n) == 1);
  CHECK(quic_client_is_connected(&c) == 1);
}

/* A Certificate handshake message wrapping the realchain [leaf, int]. */
static usz rc_cert_msg(u8 *out) {
  const u8 *certs[2] = {quic_realchain_leaf_der, quic_realchain_int_der};
  usz       lens[2]  = {
      sizeof(quic_realchain_leaf_der), sizeof(quic_realchain_int_der)};
  usz off = QUIC_HS_HEADER + 4, list, body;
  for (usz i = 0; i < 2; i++) {
    usz n        = lens[i];
    out[off]     = (u8)(n >> 16);
    out[off + 1] = (u8)(n >> 8);
    out[off + 2] = (u8)n;
    for (usz j = 0; j < n; j++) out[off + 3 + j] = certs[i][j];
    out[off + 3 + n] = 0;
    out[off + 4 + n] = 0;
    off += n + 5;
  }
  list                    = off - QUIC_HS_HEADER - 4;
  body                    = list + 4;
  out[0]                  = 0x0b;
  out[1]                  = (u8)(body >> 16);
  out[2]                  = (u8)(body >> 8);
  out[3]                  = (u8)body;
  out[QUIC_HS_HEADER]     = 0;
  out[QUIC_HS_HEADER + 1] = (u8)(list >> 16);
  out[QUIC_HS_HEADER + 2] = (u8)(list >> 8);
  out[QUIC_HS_HEADER + 3] = (u8)list;
  return off;
}

/* One DER INTEGER from a 32-byte big-endian scalar. */
static usz rc_der_int(u8 *out, const u8 v[32]) {
  usz n = 32, pad;
  while (n > 1 && v[32 - n] == 0) n--;
  pad    = (v[32 - n] & 0x80) ? 1 : 0;
  out[0] = 0x02;
  out[1] = (u8)(n + pad);
  if (pad) out[2] = 0;
  for (usz i = 0; i < n; i++) out[2 + pad + i] = v[32 - n + i];
  return 2 + pad + n;
}

static const char rc_cv_ctx[] = "TLS 1.3, server CertificateVerify";

/* Sign a CertificateVerify as the realchain leaf over the client's current
 * transcript (through Certificate) and frame it, scheme ecdsa_secp256r1. */
static usz rc_sign_cv(const quic_fullhs *h, u8 *cv) {
  u8  th[32], content[130], chash[32], r[32], s[32], der[80];
  usz rn, sn, dn, body;
  quic_sha256(h->tr, h->tr_len, th);
  for (usz i = 0; i < 64; i++) content[i] = 0x20;
  for (usz i = 0; i < 33; i++) content[64 + i] = (u8)rc_cv_ctx[i];
  content[97] = 0x00;
  for (usz i = 0; i < 32; i++) content[98 + i] = th[i];
  quic_sha256(content, 130, chash);
  CHECK(quic_p256sign_sign(quic_realchain_leaf_priv, chash, r, s) == 1);
  rn     = rc_der_int(der + 2, r);
  sn     = rc_der_int(der + 2 + rn, s);
  der[0] = 0x30;
  der[1] = (u8)(rn + sn);
  dn     = 2 + rn + sn;
  body   = 4 + dn;
  cv[0]  = 0x0f;
  cv[1]  = 0;
  cv[2]  = (u8)(body >> 8);
  cv[3]  = (u8)body;
  cv[4]  = (u8)(QUIC_TLS_SCHEME_ECDSA_P256 >> 8);
  cv[5]  = (u8)QUIC_TLS_SCHEME_ECDSA_P256;
  cv[6]  = (u8)(dn >> 8);
  cv[7]  = (u8)dn;
  for (usz i = 0; i < dn; i++) cv[8 + i] = der[i];
  return 4 + body;
}

/* RFC 5280 6.1 + RFC 6125: the real-web shape end to end. The wire carries
 * [leaf, int]; the store holds the root; the leaf names example.com; the
 * clock is in the window; the CV is ECDSA-signed by the leaf key. The client
 * reaches connected with every check armed. */
static void test_client_castore_confirmed(void) {
  quic_client        c;
  quic_fullhs        sv;
  quic_tlsdriver     svtls;
  quic_castore       store;
  quic_castore_entry roots[2];
  u8                 certmsg[1024], cv[256], svfin[64];
  u8                 cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
  usz                n, cv_len, fn;

  for (usz i = 0; i < 32; i++) {
    cl_priv[i] = (u8)(1 + i);
    sv_priv[i] = (u8)(200 - i);
  }
  quic_x25519_base(cl_pub, cl_priv);
  quic_x25519_base(sv_pub, sv_priv);
  quic_tlsdriver_init(&c.tls, cl_priv, cl_pub, 0);
  quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);
  client_reach_hs_secret(&c.tls, &svtls, sv_pub);
  CHECK(quic_fullhs_init(&c.hs, &c.tls, quic_span_of(fullhs_sh, sizeof(fullhs_sh))) == 1);
  CHECK(quic_fullhs_init(&sv, &svtls, quic_span_of(fullhs_sh, sizeof(fullhs_sh))) == 1);
  c.phase = QUIC_CLIENT_HS_AUTH;
  c.fd    = -1;
  /* what feed_initial injects for a fully armed client */
  quic_fullhs_set_policy(
      &c.hs, 20270101000000ULL, quic_span_of((const u8 *)"example.com", 11));
  quic_castore_init(&store, roots, 2);
  CHECK(
      quic_castore_add(
          &store,
          quic_span_of(
              quic_realchain_root_der, sizeof(quic_realchain_root_der))) == 1);
  quic_fullhs_set_castore(&c.hs, &store);

  n = rc_cert_msg(certmsg);
  CHECK(quic_client_feed(&c, certmsg, n) == 1);
  cv_len = rc_sign_cv(&c.hs, cv);

  /* mirror server advances its transcript with the same flight */
  CHECK(quic_fullhs_recv_cert(&sv, certmsg, n) == 1);
  CHECK(
      quic_fullhs_recv_certverify(&sv, quic_span_of(cv, cv_len), QUIC_TLS_SCHEME_ECDSA_P256) == 1);
  {
    quic_obuf ob = quic_obuf_of(svfin, sizeof(svfin));
    CHECK(quic_fullhs_send_finished(&sv, &ob) == 1);
    fn = ob.len;
  }

  CHECK(quic_client_feed(&c, cv, cv_len) == 1);
  CHECK(quic_client_feed(&c, svfin, fn) == 1);
  CHECK(quic_client_is_connected(&c) == 1);
}

/* A store that cannot anchor the presented chain keeps the client from ever
 * connecting (through the real feed path, set_castore plumbing included). */
static void test_client_castore_wrong_root(void) {
  quic_client        c;
  quic_tlsdriver     svtls;
  quic_castore       store;
  quic_castore_entry roots[2];
  quic_castore_init(&store, roots, 2);
  CHECK(
      quic_castore_add(
          &store,
          quic_span_of(
              quic_realchain_root_der, sizeof(quic_realchain_root_der))) == 1);
  policy_client(&c, &svtls, 0, 0, 0);
  quic_client_set_castore(&c, &store);
  quic_fullhs_set_castore(&c.hs, c.castore); /* as feed_initial would */
  /* the golden self-signed cert cannot anchor to the realchain root */
  CHECK(quic_client_feed(&c, fullhs_cert_msg, sizeof(fullhs_cert_msg)) == 0);
  CHECK(quic_client_is_connected(&c) == 0);
}

void test_client(void) {
  test_client_initial_padded();
  test_client_feed_serverhello();
  test_client_e2e_confirmed();
  test_client_expired_now();
  test_client_wrong_host();
  test_client_policy_valid();
  test_client_castore_confirmed();
  test_client_castore_wrong_root();
}
