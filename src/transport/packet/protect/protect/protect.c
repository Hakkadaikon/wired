#include "transport/packet/protect/protect/protect.h"

#include "crypto/symmetric/aead/gcm/gcm.h"
#include "transport/packet/protect/hp/hp.h"

void quic_protect_nonce(
    const u8 iv[QUIC_INITIAL_IV], u64 pn, u8 nonce[QUIC_INITIAL_IV]) {
  for (usz i = 0; i < QUIC_INITIAL_IV; i++) nonce[i] = iv[i];
  /* XOR the 64-bit pn into the low 8 bytes (iv is left-padded). */
  for (usz i = 0; i < 8; i++)
    nonce[QUIC_INITIAL_IV - 1 - i] ^= (u8)(pn >> (8 * i));
}

/* Copy the header into io->out and seal the payload after it, returning the
 * total length (header + ciphertext + tag) or 0 on overflow. */
static usz seal_into(
    const quic_initial_keys *keys, const quic_protect_seal_io *io) {
  u8          nonce[QUIC_INITIAL_IV];
  quic_aes128 aead;
  u8         *out  = io->out.p;
  usz         need = io->hdr.n + io->payload.n + QUIC_GCM_TAG;
  if (need > io->out.n) return 0;
  for (usz i = 0; i < io->hdr.n; i++) out[i] = io->hdr.p[i];
  quic_protect_nonce(keys->iv, io->pn, nonce);
  quic_aes128_init(&aead, keys->key);
  quic_gcm_ctx g = {&aead, nonce, io->hdr};
  quic_gcm_seal(&g, io->payload, out + io->hdr.n);
  return need;
}

/* Apply header protection: sample 16 bytes at pn+4, mask byte0 and the
 * pn.n packet-number bytes at pn.p. */
static void protect_header(const quic_aes128 *hp_aes, u8 *pkt, quic_mspan pn) {
  u8             mask[5];
  quic_hp_fields f = {pkt, pn.p, pn.n, QUIC_HP_LONG_MASK};
  quic_hp_mask(hp_aes, pn.p + 4, mask);
  quic_hp_apply(mask, &f);
}

usz quic_protect_seal(
    const quic_protect_keys *k, const quic_protect_seal_io *io) {
  usz total = seal_into(k->keys, io);
  if (total == 0) return 0;
  protect_header(
      k->hp, io->out.p, quic_mspan_of(io->out.p + io->pn_off, io->pn_len));
  return total;
}

usz quic_protect_open(
    const quic_protect_keys *k, const quic_protect_open_io *io) {
  u8          nonce[QUIC_INITIAL_IV];
  quic_aes128 aead;
  u8         *pkt    = io->pkt.p;
  usz         ct_len = io->pkt.n - io->hdr_len - QUIC_GCM_TAG;
  /* XOR self-inverse: removes HP */
  protect_header(k->hp, pkt, quic_mspan_of(pkt + io->pn_off, io->pn_len));
  quic_protect_nonce(k->keys->iv, io->pn, nonce);
  quic_aes128_init(&aead, k->keys->key);
  quic_gcm_ctx g = {&aead, nonce, {pkt, io->hdr_len}};
  if (!quic_gcm_open(
          &g, quic_span_of(pkt + io->hdr_len, ct_len + QUIC_GCM_TAG),
          pkt + io->hdr_len))
    return 0;
  return ct_len;
}
