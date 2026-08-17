#include "crypto/asymmetric/ecc/p256/p256_ecdhe.h"
#include "test.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tlsdriver/tlsdriver.h"
#include "tls/handshake/roles/shbuild/shbuild.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

/* RFC 8446-101 stage C: secp256r1 (P-256) as the negotiated ECDHE group,
 * exercised end to end the same way test_tlsdriver_real_ecdhe_agree exercises
 * x25519 -- a real ClientHello/ServerHello pair, driven entirely through
 * quic_tlsdriver, reaching the same shared secret on both sides. */

/* Give d a P-256 key pair for group secp256r1: my_priv is the 32-byte
 * scalar, my_pub the 65-byte SEC1 uncompressed point quic_tlsdriver_init's
 * frozen 32-byte x25519 copy never reaches (quic_tlsdriver_set_group's own
 * doc: the caller writes the group's real key pair in afterward). */
static void set_p256_identity(quic_tlsdriver* d, const u8 priv[32]) {
  quic_tlsdriver_set_group(d, QUIC_GROUP_SECP256R1);
  for (usz i = 0; i < 32; i++) d->my_priv[i] = priv[i];
  CHECK(quic_p256_pubkey_encode(d->my_pub, priv) == 1);
}

/* Build a minimal ServerHello (RFC 8446 4.1.3) carrying supported_versions
 * and a single secp256r1 key_share for pub (65-byte SEC1 uncompressed). */
static usz build_sh_p256(u8* out, usz cap, const u8 pub[QUIC_P256_PUBKEY_LEN]) {
  u8                    random[32];
  wired_obuf            ob = quic_obuf_of(out, cap);
  quic_shbuild_group_in in = {
      random,
      wired_span_of((const u8*)0, 0),
      0x1301,
      pub,
      0,
      QUIC_GROUP_SECP256R1,
      QUIC_P256_PUBKEY_LEN};
  for (usz i = 0; i < 32; i++) random[i] = (u8)(0x10 + i);
  CHECK(quic_shbuild_server_hello_group(&in, &ob) == 1);
  return ob.len;
}

/* Wrap a whole TLS message in one CRYPTO frame at offset 0. */
static usz wrap_crypto_p256(u8* out, usz cap, const u8* msg, usz n) {
  wired_obuf                 ob  = quic_obuf_of(out, cap);
  quic_crypto_stream_emit_in ein = {0, 256};
  CHECK(quic_crypto_stream_emit(wired_span_of(msg, n), &ein, &ob) == 1);
  return ob.len;
}

/* A client and a server agree on the same ECDHE shared secret over real TLS
 * bytes carried in CRYPTO frames, negotiating secp256r1 instead of the
 * default x25519 (RFC 8446 4.2.7 NamedGroup). The server reaching a shared
 * secret directly from the client's ClientHello (no HelloRetryRequest,
 * RFC 8446 4.1.4) also proves its key_share scan looks for its own
 * negotiated group, not a hardcoded x25519 -- a secp256r1-only ClientHello
 * is never mistaken for one missing a key_share. */
static void test_tlsdriver_p256_ecdhe_agree(void) {
  u8             cl_priv[32], sv_priv[32];
  u8             frame[1024], sh[512];
  usz            fl, shn;
  quic_tlsdriver cl, sv;
  const u8 *     cs, *ss;

  CHECK(quic_p256_keygen(cl_priv) == 1);
  CHECK(quic_p256_keygen(sv_priv) == 1);

  /* quic_tlsdriver_init's my_priv/my_pub arguments are a placeholder 32-byte
   * x25519-shaped pair here -- never used, since set_p256_identity below
   * overwrites d->my_priv/d->my_pub with the real P-256 pair before
   * anything is built or parsed. */
  {
    u8 unused_pair[32] = {0};
    quic_tlsdriver_init(&cl, unused_pair, unused_pair, 0);
    quic_tlsdriver_init(&sv, unused_pair, unused_pair, 1);
  }
  set_p256_identity(&cl, cl_priv);
  set_p256_identity(&sv, sv_priv);

  /* client -> server: real ClientHello (secp256r1 key_share) in a CRYPTO
   * frame */
  {
    wired_obuf ob = quic_obuf_of(frame, sizeof(frame));
    CHECK(quic_tlsdriver_client_hello(&cl, &ob) == 1);
    fl = ob.len;
  }
  CHECK(fl != 0);
  CHECK(quic_tlsdriver_recv_crypto(&sv, frame, fl) == 1);
  CHECK(quic_tlsdriver_handshake_secret_ready(&sv) == 1);

  /* server -> client: ServerHello (server's secp256r1 key_share) in a
   * CRYPTO frame */
  shn = build_sh_p256(sh, sizeof(sh), sv.my_pub);
  fl  = wrap_crypto_p256(frame, sizeof(frame), sh, shn);
  CHECK(quic_tlsdriver_recv_crypto(&cl, frame, fl) == 1);
  CHECK(quic_tlsdriver_handshake_secret_ready(&cl) == 1);

  /* both reached the same shared secret over real wire bytes */
  CHECK(quic_tlsdriver_shared_secret(&cl, &cs) == 1);
  CHECK(quic_tlsdriver_shared_secret(&sv, &ss) == 1);
  for (usz i = 0; i < 32; i++) CHECK(cs[i] == ss[i]);
}

void test_tlsdriver_p256(void) { test_tlsdriver_p256_ecdhe_agree(); }
