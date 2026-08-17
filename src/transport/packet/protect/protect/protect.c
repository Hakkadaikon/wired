#include "transport/packet/protect/protect/protect.h"

#include "crypto/symmetric/aead/gcm/gcm.h"
#include "tls/handshake/core/tls/aead_params.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/protect_suite/aead_suite.h"
#include "transport/packet/protect/protect_suite/hp_suite.h"

void protect_nonce(const u8 iv[INITIAL_IV], u64 pn, u8 nonce[INITIAL_IV]) {
  for (usz i = 0; i < INITIAL_IV; i++) nonce[i] = iv[i];
  /* XOR the 64-bit pn into the low 8 bytes (iv is left-padded). */
  for (usz i = 0; i < 8; i++) nonce[INITIAL_IV - 1 - i] ^= (u8)(pn >> (8 * i));
}

/* Copy the header into io->out and seal the payload after it, returning the
 * total length (header + ciphertext + tag) or 0 on overflow. */
static usz seal_into(const initial_keys* keys, const protect_seal_io* io) {
  u8     nonce[INITIAL_IV];
  aes128 aead;
  u8*    out  = io->out.p;
  usz    need = io->hdr.n + io->payload.n + GCM_TAG;
  if (need > io->out.n) return 0;
  for (usz i = 0; i < io->hdr.n; i++) out[i] = io->hdr.p[i];
  protect_nonce(keys->iv, io->pn, nonce);
  aes128_init(&aead, keys->key);
  gcm_ctx g = {&aead, nonce, io->hdr};
  gcm_seal(&g, io->payload, out + io->hdr.n);
  return need;
}

/* Apply header protection: sample 16 bytes at pn+4, mask byte0 and the
 * pn.n packet-number bytes at pn.p. */
static void protect_header(const aes128* hp_aes, u8* pkt, wired_mspan pn) {
  u8        mask[5];
  hp_fields f = {pkt, pn.p, pn.n, HP_LONG_MASK};
  hp_mask(hp_aes, pn.p + 4, mask);
  hp_apply(mask, &f);
}

usz protect_seal(const protect_keys* k, const protect_seal_io* io) {
  usz total = seal_into(k->keys, io);
  if (total == 0) return 0;
  protect_header(
      k->hp, io->out.p, wired_mspan_of(io->out.p + io->pn_off, io->pn_len));
  return total;
}

usz protect_open(const protect_keys* k, const protect_open_io* io) {
  u8     nonce[INITIAL_IV];
  aes128 aead;
  u8*    pkt    = io->pkt.p;
  usz    ct_len = io->pkt.n - io->hdr_len - GCM_TAG;
  /* XOR self-inverse: removes HP */
  protect_header(k->hp, pkt, wired_mspan_of(pkt + io->pn_off, io->pn_len));
  protect_nonce(k->keys->iv, io->pn, nonce);
  aes128_init(&aead, k->keys->key);
  gcm_ctx g = {&aead, nonce, {pkt, io->hdr_len}};
  if (!gcm_open(
          &g, wired_span_of(pkt + io->hdr_len, ct_len + GCM_TAG),
          pkt + io->hdr_len))
    return 0;
  return ct_len;
}

static void protect_copy_hdr(u8* out, wired_span hdr) {
  for (usz i = 0; i < hdr.n; i++) out[i] = hdr.p[i];
}

/* Copy the header into io->out and seal the payload after it under `suite`,
 * returning the total length (header + ciphertext + tag) or 0 on
 * overflow/unknown suite. */
static usz seal_into_suite(
    u16 suite, const initial_keys* keys, const protect_seal_io* io) {
  u8*           out  = io->out.p;
  usz           need = io->hdr.n + io->payload.n + aead_tag_len(suite);
  aead_suite_op op;
  if (need > io->out.n) return 0;
  protect_copy_hdr(out, io->hdr);
  /* aead_suite_seal derives the nonce itself (iv XOR pn); op.iv is the
   * raw key IV, not a precomputed nonce (RFC 9001 5.3). */
  op = (aead_suite_op){suite, keys->key, keys->iv, io->pn, io->hdr};
  return aead_suite_seal(&op, io->payload, out + io->hdr.n) ? need : 0;
}

/* Apply header protection under `suite` (AES-ECB or ChaCha20, RFC 9001
 * 5.4.1/5.4.3) using keys->hp's raw bytes. Returns 0 on an unrecognized
 * suite. */
static int protect_header_suite(
    u16 suite, const u8* hp_key, u8* pkt, wired_mspan pn) {
  u8        mask[5];
  hp_fields f = {pkt, pn.p, pn.n, HP_LONG_MASK};
  if (!hp_suite_mask(suite, hp_key, pn.p + 4, mask)) return 0;
  hp_apply(mask, &f);
  return 1;
}

usz protect_seal_suite(
    u16 suite, const protect_keys* k, const protect_seal_io* io) {
  usz total = seal_into_suite(suite, k->keys, io);
  if (total == 0) return 0;
  if (!protect_header_suite(
          suite, k->keys->hp, io->out.p,
          wired_mspan_of(io->out.p + io->pn_off, io->pn_len)))
    return 0;
  return total;
}

usz protect_open_suite(
    u16 suite, const protect_keys* k, const protect_open_io* io) {
  u8*           pkt    = io->pkt.p;
  usz           ct_len = io->pkt.n - io->hdr_len - aead_tag_len(suite);
  aead_suite_op op;
  if (!protect_header_suite(
          suite, k->keys->hp, pkt,
          wired_mspan_of(pkt + io->pn_off, io->pn_len)))
    return 0;
  /* aead_suite_open derives the nonce itself (iv XOR pn); op.iv is the
   * raw key IV, not a precomputed nonce (RFC 9001 5.3). */
  op = (aead_suite_op){
      suite, k->keys->key, k->keys->iv, io->pn, {pkt, io->hdr_len}};
  return aead_suite_open(
      &op, wired_span_of(pkt + io->hdr_len, ct_len), pkt + io->hdr_len);
}
