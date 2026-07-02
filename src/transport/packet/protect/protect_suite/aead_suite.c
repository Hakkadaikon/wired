#include "transport/packet/protect/protect_suite/aead_suite.h"

#include "crypto/symmetric/aead/chacha/aead.h"
#include "crypto/symmetric/aead/gcm/gcm.h"
#include "tls/handshake/core/tls/cipher.h"

/* RFC 9001 5.3 nonce: iv with pn XORed into the low 8 bytes. */
static void suite_nonce(const u8 *iv, u64 pn, u8 nonce[12]) {
  for (usz i = 0; i < 12; i++) nonce[i] = iv[i];
  for (usz i = 0; i < 8; i++) nonce[11 - i] ^= (u8)(pn >> (8 * i));
}

/* One resolved seal/open after nonce derivation: key, nonce, AAD, the
 * input bytes (pt on seal, ct on open) and the destination. */
typedef struct {
  const u8 *key;
  const u8 *nonce;
  quic_span aad;
  quic_span in;
  u8       *out;
} aead_suite_io;

static usz gcm_seal(const aead_suite_io *io) {
  quic_aes128 a;
  quic_aes128_init(&a, io->key);
  quic_gcm_ctx g = {&a, io->nonce, io->aad};
  return quic_gcm_seal(&g, io->in, io->out);
}

static usz cha_seal(const aead_suite_io *io) {
  quic_chapoly_ctx c = {io->key, io->nonce, io->aad};
  return quic_chapoly_seal(&c, io->in, io->out);
}

usz quic_aead_suite_seal(const quic_aead_suite_op *op, quic_span pt, u8 *out) {
  u8 nonce[12];
  suite_nonce(op->iv, op->pn, nonce);
  aead_suite_io io = {op->key, nonce, op->aad, pt, out};
  if (op->suite == QUIC_TLS_AES_128_GCM_SHA256) return gcm_seal(&io);
  if (op->suite == QUIC_TLS_CHACHA20_POLY1305_SHA256) return cha_seal(&io);
  return 0;
}

/* io->in spans the ciphertext only; the 16-byte tag follows it in memory. */
static usz gcm_open(const aead_suite_io *io) {
  quic_aes128 a;
  quic_aes128_init(&a, io->key);
  quic_gcm_ctx g = {&a, io->nonce, io->aad};
  if (!quic_gcm_open(
          &g, quic_span_of(io->in.p, io->in.n + QUIC_GCM_TAG), io->out))
    return 0;
  return io->in.n;
}

static usz cha_open(const aead_suite_io *io) {
  quic_chapoly_ctx c = {io->key, io->nonce, io->aad};
  if (!quic_chapoly_open(
          &c, quic_span_of(io->in.p, io->in.n + QUIC_CHAPOLY_TAG), io->out))
    return 0;
  return io->in.n;
}

usz quic_aead_suite_open(const quic_aead_suite_op *op, quic_span ct, u8 *pt) {
  u8 nonce[12];
  suite_nonce(op->iv, op->pn, nonce);
  aead_suite_io io = {op->key, nonce, op->aad, ct, pt};
  if (op->suite == QUIC_TLS_AES_128_GCM_SHA256) return gcm_open(&io);
  if (op->suite == QUIC_TLS_CHACHA20_POLY1305_SHA256) return cha_open(&io);
  return 0;
}
