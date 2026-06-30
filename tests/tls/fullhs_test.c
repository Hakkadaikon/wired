#include "test.h"
#include "tls/handshake/core/fullhs/fullhs.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"
#include "fullhs_golden.h"

/* Minimal ServerHello (RFC 8446 4.1.3) carrying x25519 key_share pub. */
static usz fullhs_build_sh(u8 *out, usz cap, const u8 pub[32])
{
    usz off = quic_hs_begin(out, cap, 2), block;
    out[off] = 0x03; out[off + 1] = 0x03;
    for (usz i = 0; i < 32; i++) out[off + 2 + i] = (u8)(0x10 + i);
    out[off + 34] = 0;
    out[off + 35] = 0x13; out[off + 36] = 0x01;
    out[off + 37] = 0;
    block = off + 38;
    off = block + 2;
    out[off] = 0x00; out[off + 1] = 0x2b;
    out[off + 2] = 0x00; out[off + 3] = 2;
    out[off + 4] = 0x03; out[off + 5] = 0x04;
    off += 6;
    out[off] = 0x00; out[off + 1] = 0x33;
    out[off + 2] = 0x00; out[off + 3] = 36;
    out[off + 4] = 0x00; out[off + 5] = 0x1d;
    out[off + 6] = 0x00; out[off + 7] = 32;
    for (usz i = 0; i < 32; i++) out[off + 8 + i] = pub[i];
    off += 40;
    out[block] = (u8)((off - block - 2) >> 8);
    out[block + 1] = (u8)(off - block - 2);
    quic_hs_finish(out, off);
    (void)cap;
    return off;
}

static usz fullhs_wrap_crypto(u8 *out, usz cap, const u8 *msg, usz n)
{
    usz w = 0;
    CHECK(quic_crypto_stream_emit(msg, n, 0, 256, out, cap, &w) == 1);
    return w;
}

/* Build a CertificateVerify message: type(15) len(3) | scheme(2) | sig(2+len). */
static usz build_cv(u8 *out, u16 scheme, const u8 *sig, usz sig_len)
{
    usz body = 4 + sig_len;
    out[0] = 0x0f;
    out[1] = 0; out[2] = (u8)(body >> 8); out[3] = (u8)body;
    out[4] = (u8)(scheme >> 8); out[5] = (u8)scheme;
    out[6] = (u8)(sig_len >> 8); out[7] = (u8)sig_len;
    for (usz i = 0; i < sig_len; i++) out[8 + i] = sig[i];
    return 4 + body;
}

/* Drive both tlsdriver sides to the handshake secret over real ECDHE. */
static void reach_hs_secret(quic_tlsdriver *cl, quic_tlsdriver *sv,
                            const u8 sv_pub[32])
{
    u8 frame[1024], sh[512];
    usz fl, shn;
    CHECK(quic_tlsdriver_client_hello(cl, frame, sizeof(frame), &fl) == 1);
    CHECK(quic_tlsdriver_recv_crypto(sv, frame, fl) == 1);
    shn = fullhs_build_sh(sh, sizeof(sh), sv_pub);
    fl = fullhs_wrap_crypto(frame, sizeof(frame), sh, shn);
    CHECK(quic_tlsdriver_recv_crypto(cl, frame, fl) == 1);
    CHECK(quic_tlsdriver_handshake_secret_ready(cl) == 1);
    CHECK(quic_tlsdriver_handshake_secret_ready(sv) == 1);
}

/* Feed Certificate + CertificateVerify to one fullhs side. */
static void feed_auth(quic_fullhs *h, const u8 *cv, usz cv_len)
{
    CHECK(quic_fullhs_recv_cert(h, fullhs_cert_msg, sizeof(fullhs_cert_msg)) == 1);
    CHECK(quic_fullhs_recv_certverify(h, cv, cv_len,
                                      QUIC_TLS_SCHEME_ED25519) == 1);
}

/* RFC 8446 4.4 / RFC 9001 4.1: a full handshake reaches complete on both
 * sides, derives the application secret, installs the 1-RTT keys, confirms,
 * and discards the Handshake keys. */
static void test_fullhs_e2e(void)
{
    u8 cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
    u8 cv[256], svfin[64], clfin[64];
    usz cv_len, n;
    quic_tlsdriver cltls, svtls;
    quic_fullhs cl, sv;
    const quic_initial_keys *k;

    for (usz i = 0; i < 32; i++) { cl_priv[i] = (u8)(1 + i); sv_priv[i] = (u8)(200 - i); }
    quic_x25519_base(cl_pub, cl_priv);
    quic_x25519_base(sv_pub, sv_priv);
    quic_tlsdriver_init(&cltls, cl_priv, cl_pub, 0);
    quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);
    reach_hs_secret(&cltls, &svtls, sv_pub);

    CHECK(quic_fullhs_init(&cl, &cltls, fullhs_sh, sizeof(fullhs_sh)) == 1);
    CHECK(quic_fullhs_init(&sv, &svtls, fullhs_sh, sizeof(fullhs_sh)) == 1);

    cv_len = build_cv(cv, QUIC_TLS_SCHEME_ED25519, fullhs_cv_sig,
                      sizeof(fullhs_cv_sig));

    /* server authenticates itself into its own transcript, then signs Finished */
    feed_auth(&sv, cv, cv_len);
    CHECK(quic_fullhs_send_finished(&sv, svfin, sizeof(svfin), &n) == 1);

    /* client receives Certificate, CertificateVerify, server Finished */
    feed_auth(&cl, cv, cv_len);
    CHECK(quic_fullhs_recv_finished(&cl, svfin, n) == 1);
    CHECK(quic_fullhs_is_complete(&cl) == 1);

    /* server completes by receiving the client's Finished */
    CHECK(quic_fullhs_send_finished(&cl, clfin, sizeof(clfin), &n) == 1);
    CHECK(quic_fullhs_recv_finished(&sv, clfin, n) == 1);
    CHECK(quic_fullhs_is_complete(&sv) == 1);

    /* both derive the application secret and install 1-RTT keys */
    CHECK(quic_fullhs_advance_application(&cl) == 1);
    CHECK(quic_fullhs_advance_application(&sv) == 1);
    CHECK(quic_keyset_for_level(&cltls.keys, QUIC_LEVEL_ONERTT, &k) == 1);
    CHECK(quic_keyset_for_level(&svtls.keys, QUIC_LEVEL_ONERTT, &k) == 1);

    /* HANDSHAKE_DONE confirms and discards the Handshake keys */
    CHECK(quic_keyset_for_level(&cltls.keys, QUIC_LEVEL_HANDSHAKE, &k) == 1);
    CHECK(quic_fullhs_confirmed(&cl) == 1);
    CHECK(quic_fullhs_is_confirmed(&cl) == 1);
    CHECK(quic_keyset_for_level(&cltls.keys, QUIC_LEVEL_HANDSHAKE, &k) == 0);
}

/* RFC 8446 4.4.3: a bad CertificateVerify signature keeps the auth gate shut,
 * so the server's Finished is never accepted and the handshake never completes. */
static void test_fullhs_bad_certverify(void)
{
    u8 cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
    u8 cv[256], badsig[64];
    usz cv_len;
    quic_tlsdriver cltls, svtls;
    quic_fullhs cl;

    for (usz i = 0; i < 32; i++) { cl_priv[i] = (u8)(1 + i); sv_priv[i] = (u8)(200 - i); }
    quic_x25519_base(cl_pub, cl_priv);
    quic_x25519_base(sv_pub, sv_priv);
    quic_tlsdriver_init(&cltls, cl_priv, cl_pub, 0);
    quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);
    reach_hs_secret(&cltls, &svtls, sv_pub);
    CHECK(quic_fullhs_init(&cl, &cltls, fullhs_sh, sizeof(fullhs_sh)) == 1);

    for (usz i = 0; i < 64; i++) badsig[i] = fullhs_cv_sig[i];
    badsig[0] ^= 0x01;
    cv_len = build_cv(cv, QUIC_TLS_SCHEME_ED25519, badsig, sizeof(badsig));

    CHECK(quic_fullhs_recv_cert(&cl, fullhs_cert_msg, sizeof(fullhs_cert_msg)) == 1);
    CHECK(quic_fullhs_recv_certverify(&cl, cv, cv_len,
                                      QUIC_TLS_SCHEME_ED25519) == 0);
    CHECK(quic_fullhs_is_complete(&cl) == 0);
}

/* RFC 8446 4.4.4: a tampered Finished verify_data is rejected and the
 * handshake stays incomplete. */
static void test_fullhs_bad_finished(void)
{
    u8 cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
    u8 cv[256], svfin[64];
    usz cv_len, n;
    quic_tlsdriver cltls, svtls;
    quic_fullhs cl, sv;

    for (usz i = 0; i < 32; i++) { cl_priv[i] = (u8)(1 + i); sv_priv[i] = (u8)(200 - i); }
    quic_x25519_base(cl_pub, cl_priv);
    quic_x25519_base(sv_pub, sv_priv);
    quic_tlsdriver_init(&cltls, cl_priv, cl_pub, 0);
    quic_tlsdriver_init(&svtls, sv_priv, sv_pub, 1);
    reach_hs_secret(&cltls, &svtls, sv_pub);
    CHECK(quic_fullhs_init(&cl, &cltls, fullhs_sh, sizeof(fullhs_sh)) == 1);
    CHECK(quic_fullhs_init(&sv, &svtls, fullhs_sh, sizeof(fullhs_sh)) == 1);

    cv_len = build_cv(cv, QUIC_TLS_SCHEME_ED25519, fullhs_cv_sig,
                      sizeof(fullhs_cv_sig));
    feed_auth(&sv, cv, cv_len);
    CHECK(quic_fullhs_send_finished(&sv, svfin, sizeof(svfin), &n) == 1);
    feed_auth(&cl, cv, cv_len);

    svfin[QUIC_HS_HEADER] ^= 0x01; /* corrupt verify_data */
    CHECK(quic_fullhs_recv_finished(&cl, svfin, n) == 0);
    CHECK(quic_fullhs_is_complete(&cl) == 0);
}

void test_fullhs(void)
{
    test_fullhs_e2e();
    test_fullhs_bad_certverify();
    test_fullhs_bad_finished();
}
