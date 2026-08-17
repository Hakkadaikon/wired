#include "castore_golden.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/pki/cert/selfcert/selfcert.h"
#include "realchain_golden.h"
#include "test.h"
#include "tls/handshake/core/fullhs/fullhs.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/sflight/certmsg.h"
#include "tls/handshake/roles/sflight/certverify_build.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

/* Minimal ServerHello (RFC 8446 4.1.3) carrying an x25519 key_share pub. */
static usz fc_build_sh(u8* out, usz cap, const u8 pub[32]) {
  usz off      = hs_begin(out, cap, 2), block;
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
  hs_finish(out, off);
  (void)cap;
  return off;
}

/* Fresh client tlsdriver at the handshake secret over real ECDHE, fullhs
 * seeded from the real ServerHello bytes exchanged (RFC 8446 4.4.1: the
 * transcript is ClientHello||ServerHello, not an unrelated golden constant).
 * Hands back sh and *shn so a caller needing a matching server-side fullhs
 * can reuse the same transcript. */
static void fc_new_client(
    tlsdriver* cl, tlsdriver* sv, fullhs* h, u8* sh, usz* shn) {
  u8  cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
  u8  frame[1024];
  usz fl;
  for (usz i = 0; i < 32; i++) {
    cl_priv[i] = (u8)(1 + i);
    sv_priv[i] = (u8)(200 - i);
  }
  wired_x25519_base(cl_pub, cl_priv);
  wired_x25519_base(sv_pub, sv_priv);
  tlsdriver_init(cl, cl_priv, cl_pub, 0);
  tlsdriver_init(sv, sv_priv, sv_pub, 1);
  {
    wired_obuf ob = obuf_of(frame, sizeof(frame));
    CHECK(tlsdriver_client_hello(cl, &ob) == 1);
    fl = ob.len;
  }
  CHECK(tlsdriver_recv_crypto(sv, frame, fl) == 1);
  *shn = fc_build_sh(sh, 512, sv_pub);
  {
    wired_obuf            ob  = obuf_of(frame, sizeof(frame));
    crypto_stream_emit_in ein = {0, 256};
    CHECK(crypto_stream_emit(wired_span_of(sh, *shn), &ein, &ob) == 1);
    fl = ob.len;
  }
  CHECK(tlsdriver_recv_crypto(cl, frame, fl) == 1);
  CHECK(fullhs_init(h, cl, wired_span_of(sh, *shn)) == 1);
}

/* A freshly built self-signed Ed25519 leaf, wrapped as a TLS Certificate
 * message (RFC 8446 4.4.2) -- built once per test from seed, not a golden
 * constant, so its signature always matches whatever transcript this run's
 * real ClientHello/ServerHello exchange produced. */
static usz fc_build_cert_msg(const u8 seed[32], u8* out, usz cap) {
  u8         der[512];
  wired_obuf dob = obuf_of(der, sizeof(der));
  wired_obuf mob = obuf_of(out, cap);
  CHECK(selfcert_build(seed, &dob) == 1);
  CHECK(sflight_certificate(wired_span_of(der, dob.len), &mob) == 1);
  return mob.len;
}

/* A Certificate handshake message wrapping k DER certs, leaf first. */
static usz fc_cert_msg(
    u8* out, const u8* const* certs, const usz* lens, usz k) {
  usz off = HS_HEADER + 4, list, body;
  for (usz i = 0; i < k; i++) {
    usz n        = lens[i];
    out[off]     = (u8)(n >> 16);
    out[off + 1] = (u8)(n >> 8);
    out[off + 2] = (u8)n;
    for (usz j = 0; j < n; j++) out[off + 3 + j] = certs[i][j];
    out[off + 3 + n] = 0;
    out[off + 4 + n] = 0;
    off += n + 5;
  }
  list               = off - HS_HEADER - 4;
  body               = list + 4;
  out[0]             = 0x0b;
  out[1]             = (u8)(body >> 16);
  out[2]             = (u8)(body >> 8);
  out[3]             = (u8)body;
  out[HS_HEADER]     = 0; /* request context */
  out[HS_HEADER + 1] = (u8)(list >> 16);
  out[HS_HEADER + 2] = (u8)(list >> 8);
  out[HS_HEADER + 3] = (u8)list;
  return off;
}

static const u8* fc_realchain[2]     = {0, 0}; /* set in test entry */
static usz       fc_realchain_len[2] = {0, 0};

/* After recv_cert the caller's buffer may die; the recorded cert must
 * live in the transcript, so a freshly signed CertificateVerify (over that
 * recorded copy) still verifies. */
static void test_fullhs_chain_stale_buffer(void) {
  tlsdriver cltls, svtls;
  fullhs    cl;
  u8        sh[512], cert_seed[32], buf[768], cv[256];
  u8        th[SHA256_DIGEST];
  usz       shn, buf_len, cv_len;
  fc_new_client(&cltls, &svtls, &cl, sh, &shn);
  for (usz i = 0; i < 32; i++) cert_seed[i] = (u8)(70 + i);
  buf_len = fc_build_cert_msg(cert_seed, buf, sizeof(buf));
  CHECK(fullhs_recv_cert(&cl, buf, buf_len) == 1);
  for (usz i = 0; i < buf_len; i++) buf[i] = 0xaa; /* buffer dies */
  {
    wired_obuf cvob = obuf_of(cv, sizeof(cv));
    wired_sha256(cl.tr, cl.tr_len, th);
    CHECK(sflight_certificate_verify(cert_seed, th, &cvob) == 1);
    cv_len = cvob.len;
  }
  CHECK(
      fullhs_recv_certverify(
          &cl, wired_span_of(cv, cv_len), TLS_SCHEME_ED25519) == 1);
}

/* A [leaf, intermediate] message is fully retained: both certs are
 * viewable from the transcript and byte-equal to the wire DER. */
static void test_fullhs_chain_retained(void) {
  tlsdriver cltls, svtls;
  fullhs    cl;
  u8        sh[512], msg[1024];
  usz       shn, n;
  fc_new_client(&cltls, &svtls, &cl, sh, &shn);
  n = fc_cert_msg(msg, fc_realchain, fc_realchain_len, 2);
  CHECK(fullhs_recv_cert(&cl, msg, n) == 1);
  CHECK(cl.cert_count == 2);
  CHECK(cl.cert_lens[0] == sizeof(realchain_leaf_der));
  CHECK(cl.cert_lens[1] == sizeof(realchain_int_der));
  for (usz i = 0; i < cl.cert_lens[0]; i++)
    CHECK(cl.tr[cl.cert_off[0] + i] == realchain_leaf_der[i]);
  for (usz i = 0; i < cl.cert_lens[1]; i++)
    CHECK(cl.tr[cl.cert_off[1] + i] == realchain_int_der[i]);
  CHECK(cl.peer_cert == cl.tr + cl.cert_off[0]);
}

/* With the right root in the store, [leaf, int] is accepted (the
 * public-web shape: the root itself is not on the wire). */
static void test_fullhs_castore_ok(void) {
  tlsdriver     cltls, svtls;
  fullhs        cl;
  castore       store;
  castore_entry roots[2];
  u8            sh[512], msg[1024];
  usz           shn, n;
  fc_new_client(&cltls, &svtls, &cl, sh, &shn);
  castore_init(&store, roots, 2);
  CHECK(
      castore_add(
          &store,
          wired_span_of(realchain_root_der, sizeof(realchain_root_der))) == 1);
  fullhs_set_castore(&cl, &store);
  n = fc_cert_msg(msg, fc_realchain, fc_realchain_len, 2);
  CHECK(fullhs_recv_cert(&cl, msg, n) == 1);
}

/* A store without the chain's root rejects the Certificate, and the
 * auth gate stays shut for a validly signed CV and a correctly signed
 * Finished. */
static void test_fullhs_castore_wrong_root(void) {
  tlsdriver     cltls, svtls;
  fullhs        cl, sv;
  castore       store;
  castore_entry roots[2];
  u8            sh[512], cert_seed[32], cert_msg[768];
  u8            th[SHA256_DIGEST], cv[256], svfin[64];
  usz           shn, cert_msg_len, cv_len, n;
  fc_new_client(&cltls, &svtls, &cl, sh, &shn);
  CHECK(fullhs_init(&sv, &svtls, wired_span_of(sh, shn)) == 1);
  castore_init(&store, roots, 2);
  CHECK(
      castore_add(
          &store,
          wired_span_of(realchain_root_der, sizeof(realchain_root_der))) == 1);
  fullhs_set_castore(&cl, &store); /* this leaf can't anchor here */

  for (usz i = 0; i < 32; i++) cert_seed[i] = (u8)(80 + i);
  cert_msg_len = fc_build_cert_msg(cert_seed, cert_msg, sizeof(cert_msg));

  CHECK(fullhs_recv_cert(&sv, cert_msg, cert_msg_len) == 1);
  {
    wired_obuf cvob = obuf_of(cv, sizeof(cv));
    wired_sha256(sv.tr, sv.tr_len, th);
    CHECK(sflight_certificate_verify(cert_seed, th, &cvob) == 1);
    cv_len = cvob.len;
  }
  CHECK(
      fullhs_recv_certverify(
          &sv, wired_span_of(cv, cv_len), TLS_SCHEME_ED25519) == 1);
  {
    wired_obuf ob = obuf_of(svfin, sizeof(svfin));
    CHECK(fullhs_send_finished(&sv, &ob) == 1);
    n = ob.len;
  }

  CHECK(fullhs_recv_cert(&cl, cert_msg, cert_msg_len) == 0);
  CHECK(
      fullhs_recv_certverify(
          &cl, wired_span_of(cv, cv_len), TLS_SCHEME_ED25519) == 0);
  CHECK(fullhs_recv_finished(&cl, svfin, n) == 0);
  CHECK(fullhs_is_complete(&cl) == 0);
}

/* A wire chain in the wrong order ([int, leaf]) breaks the links. */
static void test_fullhs_castore_swapped(void) {
  tlsdriver     cltls, svtls;
  fullhs        cl;
  castore       store;
  castore_entry roots[2];
  const u8*     certs[2] = {realchain_int_der, realchain_leaf_der};
  usz lens[2] = {sizeof(realchain_int_der), sizeof(realchain_leaf_der)};
  u8  sh[512], msg[1024];
  usz shn, n;
  fc_new_client(&cltls, &svtls, &cl, sh, &shn);
  castore_init(&store, roots, 2);
  CHECK(
      castore_add(
          &store,
          wired_span_of(realchain_root_der, sizeof(realchain_root_der))) == 1);
  fullhs_set_castore(&cl, &store);
  n = fc_cert_msg(msg, certs, lens, 2);
  CHECK(fullhs_recv_cert(&cl, msg, n) == 0);
}

void test_fullhs_chain(void) {
  fc_realchain[0]     = realchain_leaf_der;
  fc_realchain[1]     = realchain_int_der;
  fc_realchain_len[0] = sizeof(realchain_leaf_der);
  fc_realchain_len[1] = sizeof(realchain_int_der);
  test_fullhs_chain_stale_buffer();
  test_fullhs_chain_retained();
  test_fullhs_castore_ok();
  test_fullhs_castore_wrong_root();
  test_fullhs_castore_swapped();
}
