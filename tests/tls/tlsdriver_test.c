#include "test.h"
#include "tls/handshake/core/tlsdriver/tlsdriver.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/core/tls/handshake.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

/* Build a minimal ServerHello (RFC 8446 4.1.3) carrying supported_versions
 * and a single x25519 key_share for pub. Returns total message length. */
static usz build_sh_td(u8 *out, usz cap, const u8 pub[32])
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

/* Wrap a whole TLS message in one CRYPTO frame at offset 0. */
static usz wrap_crypto(u8 *out, usz cap, const u8 *msg, usz n)
{
    usz w = 0;
    CHECK(quic_crypto_stream_emit(msg, n, 0, 256, out, cap, &w) == 1);
    return w;
}

/* RFC 9001 4 / RFC 8446 4: a client and a server agree on the same ECDHE
 * shared secret over real TLS bytes carried in CRYPTO frames. The client's
 * real ClientHello (clienthello.c) reaches the server, who parses its
 * key_share and runs X25519 (ecdhe.c); a ServerHello (serverhello.c) returns
 * to the client, who does the same. Both derive the handshake secret. */
static void test_tlsdriver_real_ecdhe_agree(void)
{
    u8 cl_priv[32], cl_pub[32], sv_priv[32], sv_pub[32];
    u8 frame[1024], sh[512];
    usz fl, shn;
    quic_tlsdriver cl, sv;
    const u8 *cs, *ss;

    for (usz i = 0; i < 32; i++) { cl_priv[i] = (u8)(1 + i); sv_priv[i] = (u8)(200 - i); }
    quic_x25519_base(cl_pub, cl_priv);
    quic_x25519_base(sv_pub, sv_priv);

    quic_tlsdriver_init(&cl, cl_priv, cl_pub, 0);
    quic_tlsdriver_init(&sv, sv_priv, sv_pub, 1);

    /* client -> server: real ClientHello in a CRYPTO frame */
    CHECK(quic_tlsdriver_client_hello(&cl, frame, sizeof(frame), &fl) == 1);
    CHECK(fl != 0);
    CHECK(quic_tlsdriver_recv_crypto(&sv, frame, fl) == 1);
    CHECK(quic_tlsdriver_handshake_secret_ready(&sv) == 1);

    /* server -> client: ServerHello (server's key_share) in a CRYPTO frame */
    shn = build_sh_td(sh, sizeof(sh), sv_pub);
    fl = wrap_crypto(frame, sizeof(frame), sh, shn);
    CHECK(quic_tlsdriver_recv_crypto(&cl, frame, fl) == 1);
    CHECK(quic_tlsdriver_handshake_secret_ready(&cl) == 1);

    /* both reached the same shared secret over real wire bytes */
    CHECK(quic_tlsdriver_shared_secret(&cl, &cs) == 1);
    CHECK(quic_tlsdriver_shared_secret(&sv, &ss) == 1);
    for (usz i = 0; i < 32; i++) CHECK(cs[i] == ss[i]);
}

/* A garbled CRYPTO frame derives nothing. */
static void test_tlsdriver_rejects_garbage(void)
{
    u8 priv[32] = {7}, pub[32], junk[8] = {0xff,0,0,0,0,0,0,0};
    quic_tlsdriver d;
    quic_x25519_base(pub, priv);
    quic_tlsdriver_init(&d, priv, pub, 1);
    CHECK(quic_tlsdriver_recv_crypto(&d, junk, sizeof(junk)) == 0);
    CHECK(quic_tlsdriver_handshake_secret_ready(&d) == 0);
}

void test_tlsdriver(void)
{
    test_tlsdriver_real_ecdhe_agree();
    test_tlsdriver_rejects_garbage();
}
